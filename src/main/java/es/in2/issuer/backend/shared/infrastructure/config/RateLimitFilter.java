package es.in2.issuer.backend.shared.infrastructure.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SEC-06: Simple per-IP rate limiter for mutating endpoints.
 * Uses a sliding window (1 minute) with a configurable max requests per IP.
 * Rejects excess requests with HTTP 429 Too Many Requests.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class RateLimitFilter implements WebFilter {

    private final int maxRequestsPerMinute;
    private final Cache<String, AtomicInteger> requestCounts;

    public RateLimitFilter(
            @Value("${issuer.api.rate-limit.max-per-minute:100}") int maxRequestsPerMinute) {
        this.maxRequestsPerMinute = maxRequestsPerMinute;
        this.requestCounts = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1))
                .maximumSize(50_000)
                .build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        HttpMethod method = exchange.getRequest().getMethod();
        if (method == null || method == HttpMethod.GET || method == HttpMethod.OPTIONS || method == HttpMethod.HEAD) {
            return chain.filter(exchange);
        }

        String clientIp = resolveClientIp(exchange);
        AtomicInteger counter = requestCounts.get(clientIp, k -> new AtomicInteger(0));
        int current = counter.incrementAndGet();

        if (current > maxRequestsPerMinute) {
            log.warn("Rate limit exceeded for IP {}: {}/{} requests/min on {} {}",
                    clientIp, current, maxRequestsPerMinute,
                    method, exchange.getRequest().getPath().value());
            exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            exchange.getResponse().getHeaders().set("Retry-After", "60");
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }

    private String resolveClientIp(ServerWebExchange exchange) {
        // Prefer X-Forwarded-For (set by nginx/reverse proxy) over direct IP
        String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        InetSocketAddress remoteAddress = exchange.getRequest().getRemoteAddress();
        return remoteAddress != null ? remoteAddress.getAddress().getHostAddress() : "unknown";
    }
}