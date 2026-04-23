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

import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_ID_HEADER;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.HEALTH_PATH;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.PROMETHEUS_PATH;

/**
 * Resolves the tenant identifier and validates it exists in {@code tenant_registry}
 * before writing it to the Reactor subscriber context.
 *
 * <p>Resolution order:
 * <ol>
 *     <li>{@code X-Tenant-Id} header (local dev via nginx; service-to-service calls;
 *         API Gateway route).</li>
 *     <li>First segment of the request host (AWS: CloudFront/ALB preserve the host,
 *         no header injection). Example: {@code kpmg.eudistack.net} &rarr; {@code kpmg}.</li>
 * </ol>
 *
 * <p>If neither produces a value (missing/empty host — internal calls, healthchecks),
 * the request passes through without a tenant in context.
 *
 * <p>Tenant-agnostic operational paths bypass this filter entirely:
 * {@value es.in2.issuer.backend.shared.domain.util.EndpointsConstants#HEALTH_PATH} and
 * {@value es.in2.issuer.backend.shared.domain.util.EndpointsConstants#PROMETHEUS_PATH}
 * — probes hit the container IP directly so the host has no tenant segment.
 *
 * <p>Returns 400 if the resolved identifier is malformed, 404 if the tenant does
 * not exist in {@code tenant_registry}.
 */
@Slf4j
@Component
public class TenantDomainWebFilter implements WebFilter {

    static final Pattern TENANT_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

    // Environment suffixes appended to tenant identifiers in non-prod DNS
    // (e.g. sandbox-stg.eudistack.net, platform-dev.eudistack.net). Stripped
    // before the registry lookup so tenant schemas stay environment-agnostic.
    private static final String[] ENV_SUFFIXES = {"-stg", "-dev", "-pre"};

    // Tenant-agnostic operational endpoints — skipped entirely to avoid noisy
    // "Tenant not found" warnings from liveness/readiness probes and Prometheus
    // scrapes that hit the container IP directly (no tenant in the Host header).
    private static final Set<String> TENANT_AGNOSTIC_PATHS = Set.of(
            HEALTH_PATH,
            PROMETHEUS_PATH
    );

    private final TenantRegistryService tenantRegistryService;

    public TenantDomainWebFilter(TenantRegistryService tenantRegistryService) {
        this.tenantRegistryService = tenantRegistryService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (TENANT_AGNOSTIC_PATHS.contains(path)) {
            return chain.filter(exchange);
        }

        String headerValue = exchange.getRequest().getHeaders().getFirst(TENANT_ID_HEADER);
        String tenantDomain;
        String source;
        if (headerValue != null && !headerValue.isBlank()) {
            tenantDomain = headerValue.trim();
            source = TENANT_ID_HEADER + " header";
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

        tenantDomain = stripEnvSuffix(tenantDomain);

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

    private static String stripEnvSuffix(String tenant) {
        for (String suffix : ENV_SUFFIXES) {
            if (tenant.endsWith(suffix)) {
                return tenant.substring(0, tenant.length() - suffix.length());
            }
        }
        return tenant;
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
