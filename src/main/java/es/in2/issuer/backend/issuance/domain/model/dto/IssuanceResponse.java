package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import lombok.Builder;

import java.util.List;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record IssuanceResponse(
        @JsonProperty("credential_offer_uri") String credentialOfferUri,
        @JsonProperty("signed_credential") String signedCredential,
        @JsonProperty("delivery_results") List<DeliveryResult> deliveryResults,
        /** Id of the stored process the Location header points to; internal, never serialized. */
        @JsonIgnore String issuanceId
) {
}
