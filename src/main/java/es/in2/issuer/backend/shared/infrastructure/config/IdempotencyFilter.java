package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;

/**
 * Idempotency of {@code POST /api/v1/issuances} by {@code X-Idempotency-Key} (per instance; sharing it
 * across instances is EUD-254). The entry is scoped to tenant, organization and caller subject, and
 * remembers a SHA-256 of the request body: the same key with another body is a conflict (422), never a
 * replay. While the first request is in flight a duplicate waits for it and gets the same response; if
 * the first does not end in a cacheable 2xx, the waiters go through the chain again.
 */
@Slf4j
@Component
@Order(1)
public class IdempotencyFilter implements WebFilter {

    static final String KEY_REUSED_TYPE = "idempotency_key_reused";
    static final String IN_PROGRESS_TYPE = "idempotency_in_progress";
    static final String PAYLOAD_TOO_LARGE_TYPE = "payload_too_large";

    private static final String IDEMPOTENCY_HEADER = "X-Idempotency-Key";

    private final IssuanceMetrics issuanceMetrics;
    private final AccessTokenService accessTokenService;
    private final ErrorResponseFactory errors;
    private final ObjectMapper objectMapper;
    private final Duration waitTimeout;
    private final int maxBodyBytes;
    private final Cache<String, CachedResponse> cache;
    private final ConcurrentMap<String, InFlight> inFlight = new ConcurrentHashMap<>();

    public IdempotencyFilter(
            @Value("${issuer.api.idempotency-ttl-seconds:3600}") long ttlSeconds,
            @Value("${issuer.api.idempotency-wait-timeout:30s}") Duration waitTimeout,
            @Value("${issuer.api.max-payload-size:262144}") long maxPayloadBytes,
            IssuanceMetrics issuanceMetrics,
            AccessTokenService accessTokenService,
            ErrorResponseFactory errors,
            ObjectMapper objectMapper) {
        this.waitTimeout = waitTimeout;
        this.maxBodyBytes = (int) Math.min(maxPayloadBytes, Integer.MAX_VALUE);
        this.issuanceMetrics = issuanceMetrics;
        this.accessTokenService = accessTokenService;
        this.errors = errors;
        this.objectMapper = objectMapper;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(ttlSeconds))
                .maximumSize(10_000)
                .build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // The path within the application: the request path carries the context path
        // (spring.webflux.base-path, /issuer), which ISSUANCES_PATH does not.
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (!HttpMethod.POST.equals(exchange.getRequest().getMethod()) || !ISSUANCES_PATH.equals(path)) {
            return chain.filter(exchange);
        }

        String idempotencyKey = exchange.getRequest().getHeaders().getFirst(IDEMPOTENCY_HEADER);
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            return chain.filter(exchange);
        }

        String tenantHeader = exchange.getRequest().getHeaders().getFirst(X_TENANT_HEADER);
        String tenantScope = (tenantHeader == null || tenantHeader.isBlank())
                ? exchange.getRequest().getURI().getHost()
                : tenantHeader;

        // The cache key binds to the caller's own identity (tenant, organization and subject):
        // scoping by tenant alone lets another caller collide on a shared or predictable key and
        // receive someone else's cached response -- including a directly-delivered signed credential
        // (EUD-167), which exists nowhere else. Both are read from the already-authenticated
        // SecurityContext, never from a fresh parse of the raw Authorization header, so a forged
        // token can never influence the key. A caller that cannot be resolved skips idempotency
        // caching entirely; it is rejected downstream on its own merits.
        String keyFingerprint = sha256Hex(idempotencyKey).substring(0, 8);
        return Mono.zip(accessTokenService.getOrganizationIdFromCurrentSession(),
                        accessTokenService.getSubjectFromCurrentSession())
                .map(caller -> Optional.of(sha256Hex(String.join("\u0000",
                        tenantScope, caller.getT1(), caller.getT2(), idempotencyKey))))
                .onErrorResume(ex -> {
                    log.warn("Could not resolve caller for idempotency scoping, skipping cache: {}", ex.toString());
                    return Mono.just(Optional.empty());
                })
                .flatMap(scopedKey -> scopedKey.isEmpty()
                        ? chain.filter(exchange)
                        : handleBody(exchange, chain, scopedKey.get(), keyFingerprint));
    }

    private Mono<Void> handleBody(ServerWebExchange exchange, WebFilterChain chain, String scopedKey,
                                  String keyFingerprint) {
        return readBody(exchange).flatMap(body -> body.isEmpty()
                ? payloadTooLarge(exchange)
                : handle(exchange, chain,
                        new Attempt(scopedKey, keyFingerprint, sha256Hex(body.get()), deadline()), body.get()));
    }

    /** The instant, on the {@link System#nanoTime()} clock, after which a waiter answers 409. */
    private long deadline() {
        return System.nanoTime() + waitTimeout.toNanos();
    }

    /** The body bytes, or empty when the body exceeds the API payload limit. */
    private Mono<Optional<byte[]>> readBody(ServerWebExchange exchange) {
        return DataBufferUtils.join(exchange.getRequest().getBody(), maxBodyBytes)
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return Optional.of(bytes);
                })
                .defaultIfEmpty(Optional.of(new byte[0]))
                .onErrorResume(DataBufferLimitException.class, ex -> Mono.just(Optional.empty()));
    }

    private Mono<Void> handle(ServerWebExchange exchange, WebFilterChain chain, Attempt attempt, byte[] bodyBytes) {
        CachedResponse cached = cache.getIfPresent(attempt.scopedKey());
        if (cached != null) {
            return replayOrConflict(exchange, cached, attempt.bodyHash(), attempt.keyFingerprint());
        }

        InFlight mine = new InFlight(attempt.bodyHash());
        InFlight existing = inFlight.putIfAbsent(attempt.scopedKey(), mine);
        if (existing != null) {
            return waitFor(exchange, chain, existing, attempt, bodyBytes);
        }

        // The previous owner may have finished between the lookup above and the reservation.
        cached = cache.getIfPresent(attempt.scopedKey());
        if (cached != null) {
            release(attempt.scopedKey(), mine, Optional.of(cached));
            return replayOrConflict(exchange, cached, attempt.bodyHash(), attempt.keyFingerprint());
        }
        return execute(exchange, chain, attempt.scopedKey(), mine, bodyBytes);
    }

    private Mono<Void> execute(ServerWebExchange exchange, WebFilterChain chain, String scopedKey,
                               InFlight mine, byte[] bodyBytes) {
        CapturingResponseDecorator decorator = new CapturingResponseDecorator(exchange);
        ServerHttpRequestDecorator requestDecorator = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.defer(() -> Flux.just(exchange.getResponse().bufferFactory().wrap(bodyBytes)));
            }
        };
        return chain.filter(exchange.mutate().request(requestDecorator).response(decorator).build())
                .doOnSuccess(ignored -> {
                    HttpStatusCode status = exchange.getResponse().getStatusCode();
                    String location = exchange.getResponse().getHeaders().getFirst("Location");
                    if (status != null && status.is2xxSuccessful()) {
                        CachedResponse response = new CachedResponse(mine.bodyHash, status, location,
                                decorator.capturedBody, decorator.capturedContentType);
                        cache.put(scopedKey, response);
                        release(scopedKey, mine, Optional.of(response));
                    }
                })
                .doFinally(signal -> release(scopedKey, mine, Optional.empty()));
    }

    /**
     * Frees the reservation and then publishes the outcome to the waiters (a second publication has no
     * effect). The order matters: a waiter that gets an empty outcome re-enters {@code handle}
     * synchronously and must not find the finished reservation still in the map.
     */
    private void release(String scopedKey, InFlight mine, Optional<CachedResponse> outcome) {
        inFlight.remove(scopedKey, mine);
        mine.outcome.tryEmitValue(outcome);
    }

    private Mono<Void> waitFor(ServerWebExchange exchange, WebFilterChain chain, InFlight existing,
                               Attempt attempt, byte[] bodyBytes) {
        if (!existing.bodyHash.equals(attempt.bodyHash())) {
            return keyReused(exchange, attempt.keyFingerprint());
        }
        log.info("Idempotency key {} in flight, waiting for the first request", attempt.keyFingerprint());
        // The deadline is fixed when the request arrives and travels through every re-entry, so the
        // total wait never exceeds the configured timeout.
        Duration remaining = Duration.ofNanos(attempt.deadlineNanos() - System.nanoTime());
        if (remaining.isNegative() || remaining.isZero()) {
            return inProgress(exchange, attempt.keyFingerprint());
        }
        return existing.outcome.asMono()
                .timeout(remaining,
                        Mono.defer(() -> inProgress(exchange, attempt.keyFingerprint())).then(Mono.empty()))
                .flatMap(outcome -> outcome.isPresent()
                        ? replayOrConflict(exchange, outcome.get(), attempt.bodyHash(), attempt.keyFingerprint())
                        : handle(exchange, chain, attempt, bodyBytes));
    }

    private Mono<Void> replayOrConflict(ServerWebExchange exchange, CachedResponse cached, String bodyHash,
                                        String keyFingerprint) {
        if (!cached.bodyHash.equals(bodyHash)) {
            return keyReused(exchange, keyFingerprint);
        }
        log.info("Idempotency key {} already processed, returning cached status {}", keyFingerprint, cached.status);
        issuanceMetrics.recordIdempotencyCacheHit();
        exchange.getResponse().setStatusCode(cached.status);
        if (cached.locationHeader != null) {
            exchange.getResponse().getHeaders().setLocation(URI.create(cached.locationHeader));
        }
        if (cached.body != null && cached.body.length > 0) {
            if (cached.contentType != null) {
                exchange.getResponse().getHeaders().setContentType(cached.contentType);
            }
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(cached.body);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        }
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> keyReused(ServerWebExchange exchange, String keyFingerprint) {
        log.warn("Idempotency key {} reused with a different request body", keyFingerprint);
        return problem(exchange, HttpStatus.UNPROCESSABLE_ENTITY, KEY_REUSED_TYPE, "Idempotency key reused",
                "The idempotency key was already used with a different request body");
    }

    private Mono<Void> inProgress(ServerWebExchange exchange, String keyFingerprint) {
        log.warn("Idempotency key {} still in progress after {}", keyFingerprint, waitTimeout);
        exchange.getResponse().getHeaders().set("Retry-After", "1");
        return problem(exchange, HttpStatus.CONFLICT, IN_PROGRESS_TYPE, "Request in progress",
                "A request with the same idempotency key is still being processed");
    }

    private Mono<Void> payloadTooLarge(ServerWebExchange exchange) {
        log.warn("Issuance request body exceeds the payload limit of {} bytes", maxBodyBytes);
        return problem(exchange, HttpStatus.PAYLOAD_TOO_LARGE, PAYLOAD_TOO_LARGE_TYPE, "Payload too large",
                "The request body exceeds the maximum allowed size");
    }

    private Mono<Void> problem(ServerWebExchange exchange, HttpStatus status, String type, String title,
                               String detail) {
        var response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        var body = errors.handleWithNow(new IllegalStateException(detail), exchange.getRequest(),
                type, title, status, detail);
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
        } catch (Exception _) {
            return response.setComplete();
        }
    }

    private static String sha256Hex(String value) {
        return sha256Hex(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static final class InFlight {
        private final String bodyHash;
        private final Sinks.One<Optional<CachedResponse>> outcome = Sinks.one();

        private InFlight(String bodyHash) {
            this.bodyHash = bodyHash;
        }
    }

    private static final class CapturingResponseDecorator extends ServerHttpResponseDecorator {

        private byte[] capturedBody;
        private MediaType capturedContentType;

        private CapturingResponseDecorator(ServerWebExchange exchange) {
            super(exchange.getResponse());
        }

        @Override
        public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
            return DataBufferUtils.join(body)
                    .flatMap(dataBuffer -> {
                        byte[] bytes = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(bytes);
                        DataBufferUtils.release(dataBuffer);
                        this.capturedBody = bytes;
                        this.capturedContentType = getHeaders().getContentType();
                        return super.writeWith(Mono.just(bufferFactory().wrap(bytes)));
                    });
        }
    }

    /**
     * One idempotent request through the filter: its scoped cache key, the key's fingerprint for the logs,
     * the hash of its body and the instant (on {@link System#nanoTime()}) after which a waiter answers 409.
     */
    private record Attempt(String scopedKey, String keyFingerprint, String bodyHash, long deadlineNanos) {}

    /**
     * A cached response. The body is compared by content and never printed: it may hold a credential
     * offer or a directly-delivered signed credential.
     */
    private record CachedResponse(String bodyHash, HttpStatusCode status, String locationHeader, byte[] body,
                                  MediaType contentType) {

        @Override
        public boolean equals(Object other) {
            return other instanceof CachedResponse(var thatHash, var thatStatus, var thatLocation, var thatBody,
                                                   var thatContentType)
                    && Objects.equals(bodyHash, thatHash)
                    && Objects.equals(status, thatStatus)
                    && Objects.equals(locationHeader, thatLocation)
                    && Arrays.equals(body, thatBody)
                    && Objects.equals(contentType, thatContentType);
        }

        @Override
        public int hashCode() {
            return 31 * Objects.hash(bodyHash, status, locationHeader, contentType) + Arrays.hashCode(body);
        }

        @Override
        public String toString() {
            return "CachedResponse[status=" + status + ", body=" + (body == null ? 0 : body.length)
                    + " bytes, redacted]";
        }
    }
}
