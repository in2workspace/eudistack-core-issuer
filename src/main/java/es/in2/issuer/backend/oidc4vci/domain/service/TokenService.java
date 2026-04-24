package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import reactor.core.publisher.Mono;

public interface TokenService {

    /**
     * @param publicIssuerBaseUrl the public base URL of this issuer as seen
     *                            by the caller (scheme + host + port +
     *                            context-path). Mandatory — service code does
     *                            not resolve URLs by itself; see
     *                            {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}.
     */
    Mono<TokenResponse> exchangeToken(TokenRequest request, String dpopHeader,
                                      String tokenEndpointUri, String publicIssuerBaseUrl);
}
