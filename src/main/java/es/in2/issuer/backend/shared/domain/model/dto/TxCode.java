package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public record TxCode(
        @JsonProperty("length") int length,
        @JsonProperty("input_mode") String inputMode,
        @JsonProperty("description") String description
) {
}
