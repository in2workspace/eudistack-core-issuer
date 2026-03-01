package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Validates that the user has a power matching the required function and action,
 * with a domain matching the tenant domain from the context.
 * SysAdmin users bypass this check (consistent with RequireOrganizationRule).
 */
@Slf4j
@RequiredArgsConstructor
public class RequirePowerRule<T> implements PolicyRule<T> {

    private final String requiredFunction;
    private final String requiredAction;

    public static <T> RequirePowerRule<T> of(String function, String action) {
        return new RequirePowerRule<>(function, action);
    }

    @Override
    public Mono<Void> evaluate(PolicyContext context, T target) {
        if (context.sysAdmin()) {
            log.info("User belongs to admin organization. Skipping power check.");
            return Mono.empty();
        }

        String tenantDomain = context.tenantDomain();
        if (tenantDomain == null || tenantDomain.isBlank()) {
            return Mono.error(new UnauthorizedRoleException(
                    "Access denied: Tenant domain is not configured"));
        }

        if (context.hasPowerWithDomain(requiredFunction, requiredAction, tenantDomain)) {
            return Mono.empty();
        }

        return Mono.error(new UnauthorizedRoleException(
                "Access denied: Required power not found (function=" + requiredFunction
                        + ", action=" + requiredAction + ", domain=" + tenantDomain + ")"));
    }
}
