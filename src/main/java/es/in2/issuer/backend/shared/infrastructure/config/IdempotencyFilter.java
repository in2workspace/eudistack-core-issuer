package es.in2.issuer.backend.shared.infrastructure.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
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
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange)
                .then(Mono.fromRunnable(() -> {
                    HttpStatus status = (HttpStatus) exchange.getResponse().getStatusCode();
                    String location = exchange.getResponse().getHeaders().getFirst("Location");
                    if (status != null && status.is2xxSuccessful()) {
                        cache.put(idempotencyKey, new CachedResponse(status, location));
                    }
                }));
    }

    private record CachedResponse(HttpStatus status, String locationHeader) {}
}
