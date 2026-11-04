package es.in2.issuer.backend.issuance.application.workflow;

import es.in2.issuer.backend.issuance.domain.model.CredentialOfferRenewal;
import reactor.core.publisher.Mono;

/** Renews the credential offer of a draft issuance ({@code renewCredentialOffer}, EUD-295). */
public interface CredentialOfferRenewalWorkflow {

    /**
     * Creates a new offer for the issuance, delivers it with the issuance's delivery mode and voids
     * the previous one. Fails with one of the renewal exceptions of
     * {@code es.in2.issuer.backend.issuance.domain.exception}.
     */
    Mono<CredentialOfferRenewal> renewCredentialOffer(String authorizationHeader, String issuanceId,
                                                      String publicIssuerBaseUrl);
}
