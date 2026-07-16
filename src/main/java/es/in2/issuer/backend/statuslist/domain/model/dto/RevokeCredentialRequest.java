package es.in2.issuer.backend.statuslist.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record RevokeCredentialRequest(
        @NotBlank(message = "issuanceId is required")
        @JsonProperty("issuanceId") String issuanceId) {
}