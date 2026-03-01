package es.in2.issuer.backend.shared.infrastructure.config;

import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_HEADER;

/**
 * Extracts the X-Tenant-Domain header injected by nginx and stores it
 * in the Reactor subscriber context so downstream services can access it.
 */
@Component
public class TenantDomainWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String tenantDomain = exchange.getRequest().getHeaders().getFirst(TENANT_DOMAIN_HEADER);
        if (tenantDomain != null && !tenantDomain.isBlank()) {
            return chain.filter(exchange)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenantDomain));
        }
        return chain.filter(exchange);
    }
}
