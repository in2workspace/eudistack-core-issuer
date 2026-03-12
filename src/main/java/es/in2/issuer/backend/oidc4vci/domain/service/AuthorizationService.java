package es.in2.issuer.backend.oidc4vci.domain.service;

import reactor.core.publisher.Mono;

import java.net.URI;

public interface AuthorizationService {

    /**
     * Process an authorization request (via PAR request_uri or direct params).
     *
     * @param requestUri PAR request_uri (if PAR was used)
     * @param clientId client identifier
     * @param responseType response_type parameter (for direct requests)
     * @param scope scope parameter (for direct requests)
     * @param state state parameter
     * @param codeChallenge code_challenge (for direct requests)
     * @param codeChallengeMethod code_challenge_method (for direct requests)
     * @param redirectUri redirect_uri
     * @param issuerState issuer_state (optional)
     * @return redirect URI with code and state
     */
    Mono<URI> authorize(
            String requestUri,
            String clientId,
            String responseType,
            String scope,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String redirectUri,
            String issuerState
    );
}
