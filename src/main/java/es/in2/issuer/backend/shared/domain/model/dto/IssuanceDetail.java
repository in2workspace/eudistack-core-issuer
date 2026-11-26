package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * An issuance process in the detail (EUD-255 contract, {@code IssuanceDetail}): every field of the
 * listing, at the same level and with the same names, plus the attestation data.
 *
 * @param summary    the fields shared with the listing and the search
 * @param credential the attestation data the process stores
 */
public record IssuanceDetail(
        @JsonUnwrapped IssuanceSummary summary,
        @JsonProperty("credential") JsonNode credential
) {
}
