package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty(value = "access_token", required = true) String accessToken,
        @JsonProperty(value = "token_type", required = true) String tokenType,
        @JsonProperty(value = "expires_in", required = true) long expiresIn,
        @JsonProperty("refresh_token") String refreshToken) {
}