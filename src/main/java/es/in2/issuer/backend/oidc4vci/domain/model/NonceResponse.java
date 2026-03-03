package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record NonceResponse(
        @JsonProperty(value = "c_nonce", required = true) String cNonce,
        @JsonProperty(value = "c_nonce_expires_in", required = true) long cNonceExpiresIn
) {
}
