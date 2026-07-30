package es.in2.issuer.backend.shared.infrastructure.controller.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

@Builder
public record DeliveryConfigDto(
        @JsonProperty("credential_configuration_id") String credentialConfigurationId,
        @JsonProperty("eligible_modes") List<String> eligibleModes
) {
}
