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

    /**
     * The person (or system) behind the current request, as the verified access token names it: the
     * mandatee's email of the attestation or, without one, the token's {@code sub}. Never read from the
     * {@code X-ID-Token}, whose signature the issuer does not verify, so an audit trail built on it cannot
     * name somebody else. Empty when the request has no verified access token or it names nobody.
     */
    Mono<String> currentPerson();
}
