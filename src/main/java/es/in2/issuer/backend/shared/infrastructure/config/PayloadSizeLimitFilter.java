package es.in2.issuer.backend.shared.infrastructure.config;

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

import java.util.Set;

/**
 * SEC-07: Enforces maximum payload size on all mutating HTTP methods (POST, PUT, PATCH).
 * Rejects requests whose Content-Length header exceeds the configured limit with HTTP 413.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class PayloadSizeLimitFilter implements WebFilter {

    private static final Set<HttpMethod> MUTATING_METHODS = Set.of(
            HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH);

    private final long maxPayloadBytes;

    public PayloadSizeLimitFilter(
            @Value("${issuer.api.max-payload-size:262144}") long maxPayloadBytes) {
        this.maxPayloadBytes = maxPayloadBytes;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        HttpMethod method = exchange.getRequest().getMethod();
        if (!MUTATING_METHODS.contains(method)) {
            return chain.filter(exchange);
        }

        long contentLength = exchange.getRequest().getHeaders().getContentLength();
        if (contentLength > maxPayloadBytes) {
            log.warn("Payload too large on {} {}: {} bytes (max: {})",
                    method, exchange.getRequest().getPath().value(),
                    contentLength, maxPayloadBytes);
            exchange.getResponse().setStatusCode(HttpStatus.PAYLOAD_TOO_LARGE);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }
}
