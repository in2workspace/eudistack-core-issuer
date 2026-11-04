package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.util.TenantIdentifiers;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.regex.Pattern;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.HEALTH_PATH;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.PROMETHEUS_PATH;

/**
 * Resolves the tenant of the request from the {@code X-Tenant} header, validates that it exists in
 * {@code tenant_registry} and stores it in the Reactor subscriber context.
 *
 * <p>The header is the only source (EUD-253 FR-01, point 12): the tenant is never deduced from the
 * request host. The entry infrastructure resolves it from {@code <tenant>.<env>.<domain>}, sets the
 * header and discards any value sent by the client (EUD-274).
 *
 * <p>Without the header (internal calls, health checks) the request passes through without a tenant
 * in context; every tenant-scoped action then fails closed downstream.
 *
 * <p>Tenant-agnostic operational paths bypass this filter entirely:
 * {@value es.in2.issuer.backend.shared.domain.util.EndpointsConstants#HEALTH_PATH} and
 * {@value es.in2.issuer.backend.shared.domain.util.EndpointsConstants#PROMETHEUS_PATH}.
 *
 * <p>A valid tenant may contain only letters, digits, hyphens and underscores.
 *
 * <p>Environment suffixes such as {@code -stg}, {@code -dev} and {@code -pre}
 * are stripped before the registry lookup.
 *
 * <p>Returns 400 if the identifier is malformed, 404 if the tenant does not exist in
 * {@code tenant_registry}.
 */
@Slf4j
@Component
public class TenantDomainWebFilter implements WebFilter {

    static final Pattern TENANT_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+$");

    // Tenant-agnostic operational endpoints are skipped entirely to avoid noisy
    // tenant resolution logs from probes and scrapes that may hit the container
    // IP directly, without a tenant in the Host header.
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
        if (isTenantAgnostic(path)) {
            log.trace("Skipping tenant resolution for tenant-agnostic path '{}'", path);
            return chain.filter(exchange);
        }

        return resolveTenant(exchange)
                .flatMap(resolvedTenant -> {
                    if (resolvedTenant == null || resolvedTenant.isBlank()) {
                        log.trace("No valid tenant resolved from request; continuing without tenant in Reactor context");
                        return chain.filter(exchange);
                    }

                    exchange.getAttributes().put(TENANT_DOMAIN_CONTEXT_KEY, resolvedTenant);
                    return chain.filter(exchange)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, resolvedTenant));
                });
    }

    private Mono<String> resolveTenant(ServerWebExchange exchange) {
        String headerValue = exchange.getRequest().getHeaders().getFirst(X_TENANT_HEADER);
        TenantCandidate headerCandidate = normalizeCandidate(headerValue, X_TENANT_HEADER + " header");

        if (headerCandidate.hasMalformedTenant()) {
            log.warn("Rejected malformed tenant identifier from {}: {}",
                    headerCandidate.source(), headerCandidate.originalTenant());
            return writeProblem(exchange, HttpStatus.BAD_REQUEST,
                    "INVALID_TENANT", "Invalid tenant identifier",
                    "Tenant identifier '" + headerCandidate.originalTenant() + "' is not a valid schema name")
                    .then(Mono.empty());
        }

        // Nothing to look up. The request can continue without tenant context.
        if (!headerCandidate.hasTenant()) {
            return Mono.just("");
        }

        return tenantRegistryService.getActiveTenantSchemas()
                .flatMap(schemas -> {
                    if (schemas.contains(headerCandidate.resolvedTenant())) {
                        log.debug("Resolved tenant '{}' from {}",
                                headerCandidate.resolvedTenant(), headerCandidate.source());
                        return Mono.just(headerCandidate.resolvedTenant());
                    }

                    log.warn("Tenant '{}' from {} not found in tenant_registry",
                            headerCandidate.resolvedTenant(), headerCandidate.source());
                    return writeProblem(exchange, HttpStatus.NOT_FOUND,
                            "TENANT_NOT_FOUND", "Tenant not found",
                            "Tenant '" + headerCandidate.resolvedTenant() + "' does not exist")
                            .then(Mono.empty());
                });
    }

    private static TenantCandidate normalizeCandidate(String tenant, String source) {
        if (tenant == null || tenant.isBlank()) {
            return TenantCandidate.empty(source);
        }

        String trimmedTenant = tenant.trim();

        if (!TENANT_NAME_PATTERN.matcher(trimmedTenant).matches()) {
            return TenantCandidate.malformed(trimmedTenant, source);
        }

        return TenantCandidate.valid(trimmedTenant, TenantIdentifiers.stripEnvSuffix(trimmedTenant), source);
    }

    private record TenantCandidate(
            String originalTenant,
            String resolvedTenant,
            String source,
            boolean malformed
    ) {

        static TenantCandidate empty(String source) {
            return new TenantCandidate(null, null, source, false);
        }

        static TenantCandidate malformed(String originalTenant, String source) {
            return new TenantCandidate(originalTenant, null, source, true);
        }

        static TenantCandidate valid(String originalTenant, String resolvedTenant, String source) {
            return new TenantCandidate(originalTenant, resolvedTenant, source, false);
        }

        boolean hasTenant() {
            return resolvedTenant != null && !resolvedTenant.isBlank();
        }

        boolean hasMalformedTenant() {
            return malformed;
        }
    }

    // Matches the configured operational paths and any sub-path beneath them
    // (e.g. /health/liveness, /health/readiness) so Actuator probes bypass
    // tenant resolution regardless of the request's Host header.
    private static boolean isTenantAgnostic(String path) {
        for (String base : TENANT_AGNOSTIC_PATHS) {
            if (path.equals(base) || path.startsWith(base + "/")) {
                return true;
            }
        }
        return false;
    }

    private static Mono<Void> writeProblem(ServerWebExchange exchange, HttpStatus status,
                                           String type, String title, String detail) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders()
                .setContentType(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON);

        String body = "{\"type\":\"" + type + "\",\"title\":\"" + title + "\",\"status\":"
                + status.value() + ",\"detail\":\"" + detail + "\"}";

        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory()
                        .wrap(body.getBytes(StandardCharsets.UTF_8)))
        );
    }
}