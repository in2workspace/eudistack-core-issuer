package es.in2.issuer.backend.issuance.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;

public record RevokeCredentialRequest(
        @JsonProperty("issuanceId") String issuanceId,
        @JsonProperty("listId") int listId) {
}
