package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record CredentialOfferGrants(
        @JsonProperty("authorization_code")
        AuthorizationCodeGrant authorizationCode,

        @JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code")
        PreAuthorizedCodeGrant preAuthorizedCode
) {
}
