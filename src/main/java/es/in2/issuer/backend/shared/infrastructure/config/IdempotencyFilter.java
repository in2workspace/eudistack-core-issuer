package es.in2.issuer.backend.shared.infrastructure.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Duration;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;

@Slf4j
@Component
@Order(1)
public class IdempotencyFilter implements WebFilter {

    private static final String IDEMPOTENCY_HEADER = "X-Idempotency-Key";

    private final IssuanceMetrics issuanceMetrics;
    private final Cache<String, CachedResponse> cache;

    public IdempotencyFilter(
            @Value("${issuer.api.idempotency-ttl-seconds:3600}") long ttlSeconds,
            IssuanceMetrics issuanceMetrics) {
        this.issuanceMetrics = issuanceMetrics;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(ttlSeconds))
                .maximumSize(10_000)
                .build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (!ISSUANCES_PATH.equals(path)) {
            return chain.filter(exchange);
        }

        String idempotencyKey = exchange.getRequest().getHeaders().getFirst(IDEMPOTENCY_HEADER);
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            return chain.filter(exchange);
        }

        CachedResponse cached = cache.getIfPresent(idempotencyKey);
        if (cached != null) {
            log.info("Idempotency key '{}' already processed, returning cached status {}", idempotencyKey, cached.status);
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

        CapturingResponseDecorator decorator = new CapturingResponseDecorator(exchange);
        return chain.filter(exchange.mutate().response(decorator).build())
                .then(Mono.fromRunnable(() -> {
                    HttpStatus status = (HttpStatus) exchange.getResponse().getStatusCode();
                    String location = exchange.getResponse().getHeaders().getFirst("Location");
                    if (status != null && status.is2xxSuccessful()) {
                        cache.put(idempotencyKey, new CachedResponse(
                                status, location, decorator.capturedBody, decorator.capturedContentType));
                    }
                }));
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

    private record CachedResponse(HttpStatus status, String locationHeader, byte[] body, MediaType contentType) {}
}
