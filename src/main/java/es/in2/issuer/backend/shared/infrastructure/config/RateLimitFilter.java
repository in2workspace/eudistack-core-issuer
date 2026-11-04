package es.in2.issuer.backend.shared.infrastructure.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SEC-06: Simple per-IP rate limiter for mutating endpoints.
 * Uses a sliding window (1 minute) with a configurable max requests per IP.
 * Rejects excess requests with HTTP 429 Too Many Requests, as an {@code application/problem+json}
 * {@code rate_limited} with {@code Retry-After} on every route (EUD-295: the issuance API contract
 * fixes that body, and the 429 is only produced here). The key (IP) and the limit belong to EUD-269.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class RateLimitFilter implements WebFilter {

    static final int RETRY_AFTER_SECONDS = 60;
    private static final byte[] RATE_LIMITED_PROBLEM = ("{\"type\":\"" + GlobalErrorTypes.RATE_LIMITED.getCode()
            + "\",\"title\":\"Too many requests\",\"status\":429,"
            + "\"detail\":\"The volume limit was exceeded. Retry after the time in Retry-After.\"}")
            .getBytes(StandardCharsets.UTF_8);

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
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            response.getHeaders().set(HttpHeaders.RETRY_AFTER, String.valueOf(RETRY_AFTER_SECONDS));
            response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(RATE_LIMITED_PROBLEM)));
        }

        return chain.filter(exchange);
    }

    private String resolveClientIp(ServerWebExchange exchange) {
        // Prefer X-Forwarded-For header (set by nginx) when available.
        // When FORWARD_HEADERS_STRATEGY=FRAMEWORK is active, Spring consumes this header
        // and rewrites remoteAddress, so the header won't be present and we fall through
        // to remoteAddress below. When the strategy is not active, the header is still
        // present and we use it directly.
        String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        InetSocketAddress remoteAddress = exchange.getRequest().getRemoteAddress();
        if (remoteAddress == null) {
            return "unknown";
        }
        // getAddress() can be null when ForwardedHeaderTransformer creates an unresolved InetSocketAddress
        return remoteAddress.getAddress() != null
                ? remoteAddress.getAddress().getHostAddress()
                : remoteAddress.getHostString();
    }
}