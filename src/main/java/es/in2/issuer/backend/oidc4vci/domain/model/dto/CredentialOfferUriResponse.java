package es.in2.issuer.backend.oidc4vci.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialOfferUriResponse(
        @JsonProperty("credential_offer_uri") String credentialOfferUri
) {
}
