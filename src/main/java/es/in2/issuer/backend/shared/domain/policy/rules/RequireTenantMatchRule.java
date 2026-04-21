package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import reactor.core.publisher.Mono;

/**
 * Validates that the tenant claim from the access token matches the tenant
 * resolved by {@code TenantDomainWebFilter} (either from the
 * {@code X-Tenant-Id} header or from the request subdomain when deployed
 * behind CloudFront/ALB).
 *
 * <p>The verifier injects the {@code tenant} claim into the access token
 * based on the OIDC client's tenant configuration. Both must match for the
 * request to be authorized.</p>
 *
 * <p>If either value is missing, the rule fails — their absence indicates
 * a misconfiguration or a bypass attempt.</p>
 */
public class RequireTenantMatchRule implements PolicyRule<Object> {

    @Override
    public Mono<Void> evaluate(PolicyContext context, Object target) {
        String tenantDomain = context.tenantDomain();
        if (tenantDomain == null || tenantDomain.isBlank()) {
            return Mono.error(new TenantMismatchException(
                    "Tenant context is required (missing X-Tenant-Id header and request host)"));
        }
        String tokenTenant = context.tokenTenant();
        if (tokenTenant == null || tokenTenant.isBlank()) {
            return Mono.error(new TenantMismatchException(
                    "Access token missing 'tenant' claim — verifier client may not have tenant configured"));
        }
        if (!tokenTenant.equalsIgnoreCase(tenantDomain)) {
            return Mono.error(new TenantMismatchException(
                    "Token tenant '" + tokenTenant +
                    "' does not match tenant header '" + tenantDomain + "'"));
        }
        return Mono.empty();
    }
}
