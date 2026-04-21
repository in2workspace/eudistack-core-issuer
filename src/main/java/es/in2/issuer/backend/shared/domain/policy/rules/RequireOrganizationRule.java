package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Validates that the user's organization matches the target organization,
 * or that the user is a sys-admin or tenant-admin (bypass).
 */
@Slf4j
public class RequireOrganizationRule implements PolicyRule<String> {

    @Override
    public Mono<Void> evaluate(PolicyContext context, String resourceOrgId) {
        if (context.sysAdmin() || context.tenantAdmin()) {
            log.info("SysAdmin or TenantAdmin — skipping organization match.");
            return Mono.empty();
        }
        if (context.organizationIdentifier().equals(resourceOrgId)) {
            return Mono.empty();
        }
        return Mono.error(new UnauthorizedRoleException(
                "Access denied: Unauthorized organization identifier"));
    }
}
