package es.in2.issuer.backend.oidc4vci.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import reactor.core.publisher.Mono;

import java.time.Instant;

public interface CredentialOfferService {

    /**
     * Creates the offer and delivers it through the requested modes. The returned
     * {@code credentialOfferUri} (modes that return one, i.e. {@code ui}) is the standard OID4VCI
     * form {@code openid-credential-offer://?credential_offer_uri=...}, never converted: the issuer
     * does not know the client's wallet (EUD-305). Only the email, which EUDIStack presents itself,
     * links to a wallet, and only when the tenant configures one ({@code issuer.wallet_url}).
     *
     * @param publicIssuerBaseUrl public base URL of this issuer resolved by
     *                            the caller via
     *                            {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver}.
     */
    Mono<CredentialOfferResult> createAndDeliverCredentialOffer(
            String issuanceId, String credentialConfigurationId, String grantType,
            String email, String delivery, String credentialOfferRefreshToken,
            String publicIssuerBaseUrl);

    /** When an offer created now stops being redeemable. */
    Instant newOfferExpiry();
}
