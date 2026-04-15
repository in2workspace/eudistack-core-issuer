package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_HEADER;

/**
 * Reads the tenant identifier from the {@code X-Tenant-Domain} header
 * and validates it exists in {@code tenant_registry} before writing
 * it to the Reactor subscriber context.
 *
 * <p>Returns 404 if the tenant does not exist.
 * Requests without the header (e.g., healthchecks) pass through.
 */
@Slf4j
@Component
public class TenantDomainWebFilter implements WebFilter {

    private final TenantRegistryService tenantRegistryService;

    public TenantDomainWebFilter(TenantRegistryService tenantRegistryService) {
        this.tenantRegistryService = tenantRegistryService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String tenantDomain = exchange.getRequest().getHeaders().getFirst(TENANT_DOMAIN_HEADER);
        if (tenantDomain == null || tenantDomain.isBlank()) {
            return chain.filter(exchange);
        }

        return tenantRegistryService.getActiveTenantSchemas()
                .flatMap(schemas -> {
                    if (!schemas.contains(tenantDomain)) {
                        log.warn("Tenant '{}' not found in tenant_registry", tenantDomain);
                        exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
                        exchange.getResponse().getHeaders().setContentType(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON);
                        String body = "{\"type\":\"TENANT_NOT_FOUND\",\"title\":\"Tenant not found\",\"status\":404,\"detail\":\"Tenant '" + tenantDomain + "' does not exist\"}";
                        return exchange.getResponse().writeWith(
                                Mono.just(exchange.getResponse().bufferFactory().wrap(body.getBytes()))
                        );
                    }
                    log.debug("Resolved tenant '{}' from {} header", tenantDomain, TENANT_DOMAIN_HEADER);
                    return chain.filter(exchange)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenantDomain));
                });
    }
}
