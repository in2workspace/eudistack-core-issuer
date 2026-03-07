package es.in2.issuer.backend.issuance.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import jakarta.validation.constraints.NotNull;

public record UpdateIssuanceStatusRequest(
        @NotNull(message = "status is required")
        @JsonProperty("status") CredentialStatusEnum status
) {
}