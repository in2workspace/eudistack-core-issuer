package es.in2.issuer.backend.shared.domain.policy;

import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireOrganizationRule;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Composes and executes policy rules with AND or OR semantics.
 * Also provides convenience methods for common policy checks.
 */
@Component
public class PolicyEnforcer {

    /**
     * Evaluates all rules in sequence (AND semantics). Fails fast on first violation.
     */
    @SafeVarargs
    public final <T> Mono<Void> enforce(PolicyContext context, T target, PolicyRule<T>... rules) {
        return Flux.fromArray(rules)
                .concatMap(rule -> rule.evaluate(context, target))
                .then();
    }

    /**
     * Evaluates rules with OR semantics. Succeeds if ANY rule passes.
     * If all rules fail, returns an error with the provided message.
     */
    @SafeVarargs
    public final <T> Mono<Void> enforceAny(PolicyContext context, T target, String failureMessage,
                                            PolicyRule<T>... rules) {
        return Flux.fromArray(rules)
                .flatMap(rule -> rule.evaluate(context, target)
                        .thenReturn(true)
                        .onErrorResume(e -> Mono.just(false)))
                .any(Boolean::booleanValue)
                .flatMap(anyPassed -> anyPassed
                        ? Mono.<Void>empty()
                        : Mono.error(new InsufficientPermissionException(failureMessage)));
    }

    /**
     * Convenience: checks that the context matches the target organization
     * (or the user is a sys-admin).
     */
    public Mono<Void> enforceOrganization(PolicyContext context, String targetOrgId) {
        return new RequireOrganizationRule().evaluate(context, targetOrgId);
    }
}
