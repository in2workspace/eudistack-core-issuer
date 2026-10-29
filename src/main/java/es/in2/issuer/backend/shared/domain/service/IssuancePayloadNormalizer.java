package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.JsonNode;

public interface IssuancePayloadNormalizer {

    /**
     * Returns the payload that the validator, the authorization policy, the credential builder and the
     * signer must all see: optional string properties declared by the credential profile that arrive as
     * {@code null} or {@code ""} are removed. The received node is never modified.
     */
    JsonNode normalize(String credentialConfigurationId, JsonNode payload);
}
