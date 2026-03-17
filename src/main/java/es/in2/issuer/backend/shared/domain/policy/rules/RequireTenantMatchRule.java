package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Composite tenant validation rule implementing defense-in-depth (AD-2).
 *
 * <p>Four sequential checks:
 * <ol>
 *   <li>The signed {@code tenant} claim MUST be present in the access token</li>
 *   <li>The signed {@code tenant} claim MUST match the {@code X-Tenant-Domain} header</li>
 *   <li>SysAdmin users bypass the power-domain check (with audit log)</li>
 *   <li>The user MUST hold an {@code Onboarding/Execute} power with {@code domain == tenantDomain}</li>
 * </ol>
 */
@Slf4j
public class RequireTenantMatchRule implements PolicyRule<Object> {

    @Override
    public Mono<Void> evaluate(PolicyContext context, Object target) {
        String tenantDomain = context.tenantDomain();
        String tokenTenant = context.tokenTenant();

        // Check 1: X-Tenant-Domain header must be present
        if (tenantDomain == null || tenantDomain.isBlank()) {
            return Mono.error(new TenantMismatchException(
                    "X-Tenant-Domain header is required"));
        }

        // Check 2: Signed tenant claim must be present in the access token
        if (tokenTenant == null || tokenTenant.isBlank()) {
            return Mono.error(new TenantMismatchException(
                    "tenant claim is required in the access token"));
        }

        // Check 3: Signed tenant claim must match the X-Tenant-Domain header
        if (!tokenTenant.equalsIgnoreCase(tenantDomain)) {
            return Mono.error(new TenantMismatchException(
                    "Token tenant '" + tokenTenant
                            + "' does not match tenant header '" + tenantDomain + "'"));
        }

        // Check 4: SysAdmin bypass (with audit trail)
        if (context.sysAdmin()) {
            log.info("Tenant match: sysAdmin bypass for tenant '{}'", tenantDomain);
            return Mono.empty();
        }

        // Check 5: User must hold Onboarding/Execute power with domain == tenantDomain
        if (context.hasPowerWithDomain("Onboarding", "Execute", tenantDomain)) {
            return Mono.empty();
        }

        return Mono.error(new TenantMismatchException(
                "No Onboarding-Execute power for tenant '" + tenantDomain + "'"));
    }
}