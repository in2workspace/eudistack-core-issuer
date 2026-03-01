package es.in2.issuer.backend.shared.domain.policy.rules;

import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyRule;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

/**
 * Validates that the user has the required role.
 */
@RequiredArgsConstructor
public class RequireRoleRule<T> implements PolicyRule<T> {

    private final String requiredRole;

    public static <T> RequireRoleRule<T> of(String role) {
        return new RequireRoleRule<>(role);
    }

    @Override
    public Mono<Void> evaluate(PolicyContext context, T target) {
        if (requiredRole.equals(context.role())) {
            return Mono.empty();
        }
        return Mono.error(new UnauthorizedRoleException(
                "Access denied: Unauthorized role to perform this credential action"));
    }
}
