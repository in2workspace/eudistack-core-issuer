package es.in2.issuer.backend.issuance.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

/**
 * The one item of {@code responses[]} (EUD-254): the requested mode, its status and, with {@code ui}
 * and {@code direct}, its {@code body}. A failed delivery is a problem response, never an item here.
 */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ChannelResponse(
        @JsonProperty("channel") String channel,
        @JsonProperty("status") int status,
        @JsonProperty("body") ChannelBody body
) {
}
