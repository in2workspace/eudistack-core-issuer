package es.in2.issuer.backend.oidc4vci.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.shared.domain.model.dto.Proof;
import lombok.Builder;

@Builder
public record CredentialRequest(
        @JsonProperty(value = "credential_configuration_id", required = true) String credentialConfigurationId,
        @JsonProperty(value = "format", required = true) String format,
        @JsonProperty(value = "proof", required = true) Proof proof) {
}
