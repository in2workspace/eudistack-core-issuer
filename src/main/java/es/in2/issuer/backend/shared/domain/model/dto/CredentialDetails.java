package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;

import java.util.UUID;
@Builder
public record CredentialDetails(
        @JsonProperty("procedure_id") UUID issuanceId,
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @JsonProperty("lifeCycleStatus") String lifeCycleStatus,
        @JsonProperty("credential") JsonNode credential,
        @JsonProperty("email") String email
) {
}
