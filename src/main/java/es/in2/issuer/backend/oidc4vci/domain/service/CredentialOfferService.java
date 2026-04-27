package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import reactor.core.publisher.Mono;

public interface CredentialOfferService {

    /**
     * @param publicIssuerBaseUrl public base URL of this issuer resolved by
     *                            the caller via
     *                            {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}.
     */
    Mono<CredentialOfferResult> createAndDeliverCredentialOffer(
            String issuanceId, String credentialConfigurationId, String grantType,
            String email, String delivery, String credentialOfferRefreshToken,
            String publicIssuerBaseUrl);
}
