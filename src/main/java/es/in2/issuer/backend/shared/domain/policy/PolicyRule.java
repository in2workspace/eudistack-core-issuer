package es.in2.issuer.backend.shared.domain.policy;

import reactor.core.publisher.Mono;

/**
 * A composable authorization rule.
 * Returns Mono.empty() on success, Mono.error() on failure.
 *
 * @param <T> the type of the target resource being authorized against
 */
@FunctionalInterface
public interface PolicyRule<T> {
    Mono<Void> evaluate(PolicyContext context, T target);
}
