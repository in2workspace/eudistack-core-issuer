package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record PushedAuthorizationResponse(
        @JsonProperty(value = "request_uri", required = true) String requestUri,
        @JsonProperty(value = "expires_in", required = true) long expiresIn
) {
}
