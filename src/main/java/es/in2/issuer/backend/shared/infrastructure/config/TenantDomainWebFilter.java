package es.in2.issuer.backend.shared.infrastructure.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Extracts the tenant identifier from the request hostname and stores it
 * in the Reactor subscriber context.
 *
 * <p>Atlassian-style: tenant is the first segment of the hostname.
 * <ul>
 *   <li>{@code kpmg.eudistack.net} → {@code kpmg}</li>
 *   <li>{@code dome.127.0.0.1.nip.io} → {@code dome}</li>
 *   <li>{@code platform.eudistack.net} → {@code platform}</li>
 * </ul>
 *
 * <p>After Spring's {@code ForwardedHeaderTransformer} has processed
 * {@code X-Forwarded-Host}, the request URI reflects the public hostname.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class TenantDomainWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String tenant = extractTenantFromHostname(exchange);
        if (tenant != null && !tenant.isBlank()) {
            log.debug("Resolved tenant '{}' from hostname '{}'", tenant, exchange.getRequest().getURI().getHost());
            return chain.filter(exchange)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
        }
        log.debug("No tenant resolved from hostname '{}'", exchange.getRequest().getURI().getHost());
        return chain.filter(exchange);
    }

    private String extractTenantFromHostname(ServerWebExchange exchange) {
        URI uri = exchange.getRequest().getURI();
        String hostname = uri.getHost();
        if (hostname == null || hostname.isBlank()) {
            return null;
        }

        // First segment of hostname = tenant (Atlassian-style)
        int dotIndex = hostname.indexOf('.');
        if (dotIndex <= 0) {
            return null;
        }

        String tenant = hostname.substring(0, dotIndex);

        if (!tenant.matches("^[a-zA-Z0-9_-]+$")) {
            log.warn("Invalid tenant identifier rejected from hostname: {}", tenant);
            return null;
        }

        return tenant.toLowerCase();
    }
}
