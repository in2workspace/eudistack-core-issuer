package es.in2.issuer.backend.issuance.domain.model.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;

public record IssuanceIdRequest(@JsonProperty(value = "procedure-id") String issuanceId) {
}
