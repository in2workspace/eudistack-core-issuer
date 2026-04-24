package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import reactor.core.publisher.Mono;

public interface CredentialIssuerMetadataService {

    /**
     * @param publicIssuerBaseUrl public base URL of this issuer resolved by
     *                            the caller via
     *                            {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}.
     */
    Mono<CredentialIssuerMetadata> getCredentialIssuerMetadata(String publicIssuerBaseUrl);
}
