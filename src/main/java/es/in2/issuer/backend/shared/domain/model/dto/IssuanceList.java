package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;

/**
 * A page of the listing (EUD-255 contract, {@code IssuanceList}). {@code next_cursor} is always
 * written, {@code null} on the last page, although the application omits null fields elsewhere.
 */
@Builder
public record IssuanceList(
        @JsonProperty("issuances") List<IssuanceSummary> issuances,
        @JsonInclude(JsonInclude.Include.ALWAYS)
        @JsonProperty("next_cursor") String nextCursor
) {
}
