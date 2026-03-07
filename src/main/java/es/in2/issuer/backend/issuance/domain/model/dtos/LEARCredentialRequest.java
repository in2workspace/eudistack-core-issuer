package es.in2.issuer.backend.issuance.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Builder;

@Builder
public record LEARCredentialRequest(@JsonProperty("credential") JsonNode credential) {
}
