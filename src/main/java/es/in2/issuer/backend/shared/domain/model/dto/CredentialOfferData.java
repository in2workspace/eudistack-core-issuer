package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

@Builder
public record CredentialOfferData(
        String issuanceId,
        CredentialOffer credentialOffer,
        String credentialEmail,
        String txCode
) {
}
