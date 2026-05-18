package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record IssuanceResponse(
        @JsonProperty("credential_offer_uri") String credentialOfferUri,
        @JsonProperty("signed_credential") String signedCredential
) {
}
