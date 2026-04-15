package es.in2.issuer.backend.shared.infrastructure.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_HEADER;

/**
 * Reads the tenant identifier from the {@code X-Tenant-Domain} header
 * (injected by nginx/ALB from the hostname) and stores it in the
 * Reactor subscriber context.
 *
 * <p>In Atlassian-style routing, nginx extracts the tenant from the first
 * segment of the hostname (e.g., {@code kpmg.eudistack.net} → {@code kpmg})
 * and passes it as {@code X-Tenant-Domain: kpmg}. In AWS, ALB does the same.
 *
 * <p>This approach ensures reliable Reactor context propagation to the
 * R2DBC {@code TenantAwareConnectionFactoryDecorator}, which reads the
 * tenant from the context to set {@code search_path}.
 */
@Slf4j
@Component
public class TenantDomainWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String tenantDomain = exchange.getRequest().getHeaders().getFirst(TENANT_DOMAIN_HEADER);
        if (tenantDomain != null && !tenantDomain.isBlank()) {
            log.debug("Resolved tenant '{}' from {} header", tenantDomain, TENANT_DOMAIN_HEADER);
            return chain.filter(exchange)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenantDomain));
        }
        log.debug("No {} header present", TENANT_DOMAIN_HEADER);
        return chain.filter(exchange);
    }
}
