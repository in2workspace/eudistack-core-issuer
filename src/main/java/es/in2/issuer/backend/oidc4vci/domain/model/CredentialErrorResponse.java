package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Credential endpoint error response per OID4VCI 1.0 §8.3.2.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialErrorResponse(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription,
        @JsonProperty("c_nonce") String cNonce,
        @JsonProperty("c_nonce_expires_in") Long cNonceExpiresIn
) {
}
