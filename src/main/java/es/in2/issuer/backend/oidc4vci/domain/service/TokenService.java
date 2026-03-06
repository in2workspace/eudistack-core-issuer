package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import reactor.core.publisher.Mono;

public interface TokenService {
    Mono<TokenResponse> exchangeToken(TokenRequest request, String dpopHeader, String tokenEndpointUri);
}