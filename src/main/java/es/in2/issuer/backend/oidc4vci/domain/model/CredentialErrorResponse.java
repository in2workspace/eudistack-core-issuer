package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Credential endpoint error response per OID4VCI 1.0 Final §8.3.1.2.
 *
 * <p>Only {@code error}, {@code error_description} and {@code error_uri} belong here. Earlier
 * drafts also carried {@code c_nonce} / {@code c_nonce_expires_in}; Final moved nonce refresh to
 * the dedicated Nonce Endpoint (§7), and the conformance suite flags those two as unknown keys
 * in this body (VCIValidateNoUnknownKeysInCredentialErrorResponse).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialErrorResponse(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription,
        @JsonProperty("error_uri") String errorUri
) {
    public CredentialErrorResponse(String error, String errorDescription) {
        this(error, errorDescription, null);
    }
}
