package es.in2.issuer.backend.statuslist.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * Body of {@code POST /api/v1/issuances/{id}/revocation}. {@code RevocationRequestValidator} checks it.
 * The reason is read as a node because Jackson would turn a number or a boolean into text, and a
 * revocation cannot be undone: only a JSON string counts as a reason.
 */
public record RevokeIssuanceRequest(@JsonProperty("reason") JsonNode reason) {

    public String reasonText() {
        return reason != null && reason.isTextual() ? reason.textValue() : null;
    }
}
