package es.in2.issuer.backend.statuslist.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Body of {@code POST /api/v1/issuances/{id}/revocation}. {@code RevocationRequestValidator} checks it. */
public record RevokeIssuanceRequest(@JsonProperty("reason") String reason) {
}
