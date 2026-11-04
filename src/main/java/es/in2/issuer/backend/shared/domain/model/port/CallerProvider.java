package es.in2.issuer.backend.shared.domain.model.port;

import es.in2.issuer.backend.shared.domain.policy.Caller;
import reactor.core.publisher.Mono;

/**
 * Source of the {@link Caller} of a request, read from its verified access token. Reading the
 * security context and the token format belongs to the infrastructure; the decision point only
 * sees the caller (hexagonal-discipline: no Spring Security or Nimbus in {@code domain/}).
 */
public interface CallerProvider {

    /** Caller of the current request, from the token the security layer already validated. */
    Mono<Caller> current();

    /** Caller of an access token (raw, without the {@code Bearer} prefix). */
    Mono<Caller> fromToken(String token);
}
