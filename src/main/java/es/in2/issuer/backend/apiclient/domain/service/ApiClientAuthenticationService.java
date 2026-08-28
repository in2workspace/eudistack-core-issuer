package es.in2.issuer.backend.apiclient.domain.service;

import es.in2.issuer.backend.apiclient.domain.exception.ApiClientAuthenticationException;
import es.in2.issuer.backend.apiclient.domain.model.AuthenticatedApiClient;
import reactor.core.publisher.Mono;

public interface ApiClientAuthenticationService {

    /**
     * Authenticates client_credentials at the token endpoint. Fail-closed:
     * every denial (unknown client, wrong secret, non-ACTIVE status,
     * repository failure) surfaces as {@link ApiClientAuthenticationException}.
     *
     * @param tenant resolved tenant identifier, used only for audit context —
     *               never for scoping the lookup (that is enforced by the
     *               tenant-bound R2DBC connection itself)
     */
    Mono<AuthenticatedApiClient> authenticateForToken(String tenant, String clientId, String clientSecret);
}
