package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import reactor.core.publisher.Mono;

public interface AccessTokenService {
    Mono<String> getCleanBearerToken(String authorizationHeader);
    Mono<String> getOrganizationId(String authorizationHeader);
    Mono<AuthorizationContext> getAuthorizationContext(String authorizationHeader);
    Mono<String> getOrganizationIdFromCurrentSession();

    /**
     * Subject of the caller, read from the already-authenticated SecurityContext: the {@code sub}
     * claim and, when absent, {@code client_id} (machine tokens). Errors with
     * {@link es.in2.issuer.backend.shared.domain.exception.InvalidTokenException} when it cannot be resolved.
     */
    Mono<String> getSubjectFromCurrentSession();
    Mono<AccessTokenContext> resolveAccessTokenContext(String authorizationHeader);

    /**
     * Extracts the {@code tenant} claim from the access token, if present. Empty (not an
     * error) when the claim is absent -- callers that require it decide how to react.
     */
    Mono<String> getTokenTenant(String authorizationHeader);
}
