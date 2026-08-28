package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationServerMetadata;
import reactor.core.publisher.Mono;

public interface AuthorizationServerMetadataService {

    /**
     * @param publicIssuerBaseUrl public base URL of this issuer (scheme + host
     *                            + port + context-path) resolved by the caller
     *                            via
     *                            {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}.
     */
    Mono<AuthorizationServerMetadata> buildAuthorizationServerMetadata(String processId,
                                                                       String publicIssuerBaseUrl);
}
