package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import reactor.core.publisher.Mono;

public interface CredentialOfferService {

    /**
     * @param publicIssuerBaseUrl public base URL of this issuer resolved by
     *                            the caller via
     *                            {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}.
     * @param publicWalletBaseUrl public base URL of the wallet PWA resolved by
     *                            the caller via
     *                            {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver#publicWalletBaseUrl}.
     *                            Used as the base of the deep-link embedded in credential-offer emails
     *                            so the wallet URL always matches the domain the user accessed the issuer from.
     */
    Mono<CredentialOfferResult> createAndDeliverCredentialOffer(
            String issuanceId, String credentialConfigurationId, String grantType,
            String email, String delivery, String credentialOfferRefreshToken,
            String publicIssuerBaseUrl, String publicWalletBaseUrl);
}
