package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.regex.Pattern;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_HEADER;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.BOOTSTRAP_PATH;

/**
 * Resolves the tenant identifier and validates it exists in {@code tenant_registry}
 * before writing it to the Reactor subscriber context.
 *
 * <p>Resolution order:
 * <ol>
 *     <li>{@code X-Tenant-Domain} header (local dev via nginx).</li>
 *     <li>First segment of the request host (AWS: CloudFront/ALB preserve the host,
 *         no header injection). Example: {@code kpmg.eudistack.net} &rarr; {@code kpmg}.</li>
 * </ol>
 *
 * <p>If neither produces a value (missing/empty host — internal calls, healthchecks),
 * the request passes through without a tenant in context.
 *
 * <p>The bootstrap endpoint ({@value es.in2.issuer.backend.shared.domain.util.EndpointsConstants#BOOTSTRAP_PATH})
 * is administrative and cross-tenant: the caller (devops script, CI/CD) declares the
 * destination tenant explicitly in the request body. This filter therefore bypasses
 * it entirely — tenant resolution and schema routing are performed by the bootstrap
 * handler itself.
 *
 * <p>Returns 400 if the resolved identifier is malformed, 404 if the tenant does
 * not exist in {@code tenant_registry}.
 */
@Slf4j
@Component
public class TenantDomainWebFilter implements WebFilter {

    static final Pattern TENANT_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

    private final TenantRegistryService tenantRegistryService;

    public TenantDomainWebFilter(TenantRegistryService tenantRegistryService) {
        this.tenantRegistryService = tenantRegistryService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (BOOTSTRAP_PATH.equals(path)) {
            return chain.filter(exchange);
        }

        String headerValue = exchange.getRequest().getHeaders().getFirst(TENANT_DOMAIN_HEADER);
        String tenantDomain;
        String source;
        if (headerValue != null && !headerValue.isBlank()) {
            tenantDomain = headerValue.trim();
            source = TENANT_DOMAIN_HEADER + " header";
        } else {
            tenantDomain = extractTenantFromHost(exchange);
            source = "request host";
        }

        if (tenantDomain == null || tenantDomain.isBlank()) {
            return chain.filter(exchange);
        }

        if (!TENANT_NAME_PATTERN.matcher(tenantDomain).matches()) {
            log.warn("Rejected malformed tenant identifier '{}' from {}", tenantDomain, source);
            return writeProblem(exchange, HttpStatus.BAD_REQUEST,
                    "INVALID_TENANT", "Invalid tenant identifier",
                    "Tenant identifier '" + tenantDomain + "' is not a valid schema name");
        }

        final String resolvedTenant = tenantDomain;
        final String resolvedSource = source;
        return tenantRegistryService.getActiveTenantSchemas()
                .flatMap(schemas -> {
                    if (!schemas.contains(resolvedTenant)) {
                        log.warn("Tenant '{}' not found in tenant_registry", resolvedTenant);
                        return writeProblem(exchange, HttpStatus.NOT_FOUND,
                                "TENANT_NOT_FOUND", "Tenant not found",
                                "Tenant '" + resolvedTenant + "' does not exist");
                    }
                    log.debug("Resolved tenant '{}' from {}", resolvedTenant, resolvedSource);
                    return chain.filter(exchange)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, resolvedTenant));
                });
    }

    private static String extractTenantFromHost(ServerWebExchange exchange) {
        String host = exchange.getRequest().getURI().getHost();
        if (host == null || host.isBlank()) {
            return null;
        }
        int dot = host.indexOf('.');
        return dot < 0 ? host : host.substring(0, dot);
    }

    private static Mono<Void> writeProblem(ServerWebExchange exchange, HttpStatus status,
                                           String type, String title, String detail) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders()
                .setContentType(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON);
        String body = "{\"type\":\"" + type + "\",\"title\":\"" + title + "\",\"status\":"
                + status.value() + ",\"detail\":\"" + detail + "\"}";
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(body.getBytes()))
        );
    }
}
