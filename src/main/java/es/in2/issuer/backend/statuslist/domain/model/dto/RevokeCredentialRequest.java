package es.in2.issuer.backend.statuslist.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RevokeCredentialRequest(
        @NotBlank(message = "issuanceId is required")
        // issuanceId ends up unsanitized in RevocationWorkflow's log statements (shared with
        // the queue-triggered path, where RevocationInstructionMessageMapper already enforces
        // this exact format via UUID.fromString) -- validating it here, at the boundary,
        // closes the same log-forging gap for the operator path instead of only downstream.
        @Pattern(regexp = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                message = "issuanceId must be a valid UUID")
        @JsonProperty("issuanceId") String issuanceId,
        @JsonProperty("reason") String reason) {
}