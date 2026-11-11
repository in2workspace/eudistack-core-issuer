package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import es.in2.issuer.backend.shared.domain.service.IdempotencyService;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;

/**
 * Idempotency of {@code POST /api/v1/issuances} (EUD-269, FR-08 of EUD-254), with the {@code X-Idempotency-Key}
 * kept in a store shared by every instance for 24 hours:
 * <ul>
 *   <li>same key and same body: the stored successful response, without creating another process;</li>
 *   <li>same key, other body: 422 {@code idempotency_key_reused};</li>
 *   <li>same key while another request with it is in progress: 409 {@code idempotency_in_progress};</li>
 *   <li>an error response is not stored: a retry after it is processed again.</li>
 * </ul>
 *
 * <p>The key is scoped to its requester (the organization for its systems, the person within it), read from
 * the verified access token, so no requester can receive another one's response -- which may be a signed
 * credential delivered directly (EUD-167). A request whose requester cannot be read is not handled here: it
 * is rejected downstream on its own merits.
 *
 * <p>The body is read up to {@code issuer.api.max-payload-size}, the limit of {@link PayloadSizeLimitFilter},
 * and a larger one is answered 413 {@code payload_too_large} (also without {@code Content-Length}, EUD-277).
 * The 409 carries {@code Retry-After: 1}: the request in progress usually ends within seconds.
 *
 * <p>The successful response is stored before it is sent, so once the client has it a retry is answered with
 * it, never as in progress. Runs after authentication and after {@link TenantDomainWebFilter}, on the path
 * within the application (without the {@code /issuer} base path). Registered as a bean in
 * {@link ApiRequestControlConfig}, so the {@code @WebFluxTest} slices do not load it.
 */
@Slf4j
public class IdempotencyFilter implements WebFilter, Ordered {

    public static final int ORDER = ApiVolumeLimitFilter.ORDER + 10;
    static final String IDEMPOTENCY_HEADER = "X-Idempotency-Key";
    /** Maximum length of the key (the {@code IdempotencyKey} parameter of the issuance API contract). */
    static final int MAX_KEY_LENGTH = 255;
    static final String PAYLOAD_TOO_LARGE_TYPE = "payload_too_large";
    /** Seconds a client is told to wait after a 409, while the request with the same key is in progress. */
    static final long IN_PROGRESS_RETRY_AFTER_SECONDS = 1;

    private final RequesterResolver requesterResolver;
    private final IdempotencyService idempotencyService;
    private final FilterProblemWriter problemWriter;
    private final IssuanceMetrics issuanceMetrics;
    private final int maxBodyBytes;

    public IdempotencyFilter(RequesterResolver requesterResolver, IdempotencyService idempotencyService,
                             FilterProblemWriter problemWriter, IssuanceMetrics issuanceMetrics, long maxBodyBytes) {
        this.requesterResolver = requesterResolver;
        this.idempotencyService = idempotencyService;
        this.problemWriter = problemWriter;
        this.issuanceMetrics = issuanceMetrics;
        this.maxBodyBytes = (int) Math.min(maxBodyBytes, Integer.MAX_VALUE);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        if (!HttpMethod.POST.equals(request.getMethod())
                || !ISSUANCES_PATH.equals(request.getPath().pathWithinApplication().value())) {
            return chain.filter(exchange);
        }
        String key = request.getHeaders().getFirst(IDEMPOTENCY_HEADER);
        if (key == null || key.isBlank()) {
            return chain.filter(exchange);
        }
        if (key.length() > MAX_KEY_LENGTH) {
            return problemWriter.write(exchange, HttpStatus.BAD_REQUEST, GlobalErrorTypes.BAD_REQUEST.getCode(),
                    "Bad request", "The X-Idempotency-Key is longer than " + MAX_KEY_LENGTH + " characters", null,
                    List.of(new GlobalErrorMessage.FieldViolation(IDEMPOTENCY_HEADER,
                            "must be at most " + MAX_KEY_LENGTH + " characters")));
        }
        return requesterResolver.current()
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(requester -> requester.isEmpty()
                        ? chain.filter(exchange)
                        : readBody(request).flatMap(body -> body.isEmpty()
                                ? payloadTooLarge(exchange)
                                : handle(exchange, chain, requester.get(), key, body.get())));
    }

    private Mono<Void> handle(ServerWebExchange exchange, WebFilterChain chain, Requester requester,
                              String key, byte[] body) {
        ServerWebExchange replayable = exchange.mutate().request(new CachedBodyRequest(exchange, body)).build();
        return idempotencyService.claim(requester, key, body)
                .flatMap(claim -> switch (claim) {
                    case IdempotencyClaim.Acquired acquired -> process(replayable, chain, acquired);
                    case IdempotencyClaim.Replay replay -> replay(exchange, replay.response());
                    case IdempotencyClaim.InProgress _ -> problemWriter.write(exchange, HttpStatus.CONFLICT,
                            GlobalErrorTypes.IDEMPOTENCY_IN_PROGRESS.getCode(), "Idempotency key in progress",
                            "Another request with the same X-Idempotency-Key is in progress",
                            IN_PROGRESS_RETRY_AFTER_SECONDS);
                    case IdempotencyClaim.KeyReused _ -> problemWriter.write(exchange,
                            HttpStatus.UNPROCESSABLE_ENTITY, GlobalErrorTypes.IDEMPOTENCY_KEY_REUSED.getCode(),
                            "Idempotency key reused",
                            "The same X-Idempotency-Key was sent with a different body", null);
                });
    }

    private Mono<Void> process(ServerWebExchange exchange, WebFilterChain chain, IdempotencyClaim.Acquired claim) {
        return Mono.deferContextual(context -> {
            RecordingResponse response = new RecordingResponse(exchange.getResponse(), claim, context);
            return chain.filter(exchange.mutate().response(response).build())
                    // A response written without a body (or not written at all) is settled here.
                    .then(Mono.defer(() -> response.settle(new byte[0])))
                    // The error is answered after this filter, by the exception handlers: it is not stored.
                    .onErrorResume(error -> response.release().then(Mono.error(error)))
                    // The client went away: whether the process was created is unknown, so the key is freed.
                    .doOnCancel(response::releaseDetached);
        });
    }

    private Mono<Void> replay(ServerWebExchange exchange, StoredResponse stored) {
        log.info("Idempotency key already processed, returning the stored status {}", stored.status());
        issuanceMetrics.recordIdempotencyCacheHit();
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatusCode.valueOf(stored.status()));
        if (stored.location() != null) {
            response.getHeaders().setLocation(URI.create(stored.location()));
        }
        if (stored.contentType() != null) {
            response.getHeaders().setContentType(MediaType.parseMediaType(stored.contentType()));
        }
        byte[] body = stored.body();
        return body.length == 0
                ? response.setComplete()
                : response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }

    /** The body, or empty when it is larger than the API payload limit. */
    private Mono<Optional<byte[]>> readBody(ServerHttpRequest request) {
        return DataBufferUtils.join(request.getBody(), maxBodyBytes)
                .map(buffer -> {
                    byte[] bytes = new byte[buffer.readableByteCount()];
                    buffer.read(bytes);
                    DataBufferUtils.release(buffer);
                    return Optional.of(bytes);
                })
                .defaultIfEmpty(Optional.of(new byte[0]))
                .onErrorResume(DataBufferLimitException.class, e -> Mono.just(Optional.empty()));
    }

    private Mono<Void> payloadTooLarge(ServerWebExchange exchange) {
        log.warn("Issuance request body exceeds the payload limit of {} bytes", maxBodyBytes);
        return problemWriter.write(exchange, HttpStatus.PAYLOAD_TOO_LARGE, PAYLOAD_TOO_LARGE_TYPE,
                "Payload too large", "The request body exceeds the maximum allowed size", null);
    }

    /** The request with its body already read, so the controller can read it again. */
    private static final class CachedBodyRequest extends ServerHttpRequestDecorator {

        private final ServerWebExchange exchange;
        private final byte[] body;

        private CachedBodyRequest(ServerWebExchange exchange, byte[] body) {
            super(exchange.getRequest());
            this.exchange = exchange;
            this.body = body;
        }

        @Override
        public Flux<DataBuffer> getBody() {
            return Flux.defer(() -> Flux.just(exchange.getResponse().bufferFactory().wrap(body)));
        }
    }

    /**
     * Settles the claim with the response before sending it: a successful one is stored, any other frees the
     * key. Settled once, whichever way the response ends.
     */
    private final class RecordingResponse extends ServerHttpResponseDecorator {

        private final IdempotencyClaim.Acquired claim;
        private final ContextView context;
        private final AtomicBoolean settled = new AtomicBoolean(false);

        private RecordingResponse(ServerHttpResponse delegate, IdempotencyClaim.Acquired claim, ContextView context) {
            super(delegate);
            this.claim = claim;
            this.context = context;
        }

        @Override
        public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
            return DataBufferUtils.join(Flux.from(body))
                    .map(buffer -> {
                        byte[] bytes = new byte[buffer.readableByteCount()];
                        buffer.read(bytes);
                        DataBufferUtils.release(buffer);
                        return bytes;
                    })
                    .defaultIfEmpty(new byte[0])
                    .flatMap(bytes -> settle(bytes)
                            .then(Mono.defer(() -> super.writeWith(Mono.just(bufferFactory().wrap(bytes))))));
        }

        @Override
        public Mono<Void> writeAndFlushWith(Publisher<? extends Publisher<? extends DataBuffer>> body) {
            return writeWith(Flux.from(body).concatMap(Flux::from));
        }

        @Override
        public Mono<Void> setComplete() {
            return settle(new byte[0]).then(Mono.defer(super::setComplete));
        }

        Mono<Void> settle(byte[] body) {
            if (!settled.compareAndSet(false, true)) {
                return Mono.empty();
            }
            HttpStatusCode status = getStatusCode();
            if (status == null || !status.is2xxSuccessful()) {
                return releaseOnce();
            }
            HttpHeaders headers = getHeaders();
            MediaType contentType = headers.getContentType();
            StoredResponse stored = new StoredResponse(status.value(),
                    contentType != null ? contentType.toString() : null,
                    headers.getFirst(HttpHeaders.LOCATION), body);
            return idempotencyService.complete(claim, stored)
                    // The response is still sent; a retry will then find the key free and be processed again.
                    .onErrorResume(e -> {
                        log.warn("Could not store the response of an idempotency key: {}", e.toString());
                        return Mono.empty();
                    });
        }

        Mono<Void> release() {
            return settled.compareAndSet(false, true) ? releaseOnce() : Mono.empty();
        }

        void releaseDetached() {
            release().contextWrite(context).subscribe(null,
                    e -> log.warn("Could not free an idempotency key after a cancelled request: {}", e.toString()));
        }

        private Mono<Void> releaseOnce() {
            return idempotencyService.release(claim)
                    .onErrorResume(e -> {
                        log.warn("Could not free an idempotency key: {}", e.toString());
                        return Mono.empty();
                    });
        }
    }
}
