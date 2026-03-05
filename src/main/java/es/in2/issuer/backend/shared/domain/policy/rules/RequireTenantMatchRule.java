package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import reactor.core.publisher.Mono;

/**
 * Validates that the tenant domain from the request header matches the
 * organizationIdentifier extracted from the bearer token.
 *
 * <p>If no tenant domain header is present, the rule passes (backwards compatible).
 * If present but mismatched, the rule fails with 403.</p>
 */
public class RequireTenantMatchRule implements PolicyRule<Object> {

    @Override
    public Mono<Void> evaluate(PolicyContext context, Object target) {
        String tenantDomain = context.tenantDomain();
        if (tenantDomain == null || tenantDomain.isBlank()) {
            return Mono.empty();
        }
        if (!tenantDomain.equals(context.organizationIdentifier())) {
            return Mono.error(new TenantMismatchException(
                    "Token organization '" + context.organizationIdentifier() +
                    "' does not match tenant header '" + tenantDomain + "'"));
        }
        return Mono.empty();
    }
}
