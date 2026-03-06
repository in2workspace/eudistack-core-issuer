package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;

@Builder
public record PreSubmittedCredentialDataRequest(
        @NotBlank(message = "credential_configuration_id is required")
        @JsonAlias("schema")
        @JsonProperty(value = "credential_configuration_id", required = true) String credentialConfigurationId,
        @NotNull(message = "payload is required")
        @JsonProperty(value = "payload", required = true) JsonNode payload,
        @JsonProperty("delivery") String delivery,
        @NotBlank(message = "email is required")
        @JsonProperty("email") String email
) {
}
