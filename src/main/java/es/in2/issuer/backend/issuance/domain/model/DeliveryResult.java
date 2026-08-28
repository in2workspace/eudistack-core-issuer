package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record DeliveryResult(
        @JsonProperty("mode") String mode,
        @JsonProperty("status") DeliveryOutcome status,
        @JsonProperty("error") String error
) {
    public enum DeliveryOutcome {
        @JsonProperty("delivered") DELIVERED,
        @JsonProperty("dispatched") DISPATCHED,
        @JsonProperty("failed") FAILED
    }

    public static DeliveryResult delivered(String mode) {
        return DeliveryResult.builder()
                .mode(mode)
                .status(DeliveryOutcome.DELIVERED)
                .build();
    }

    public static DeliveryResult dispatched(String mode) {
        return DeliveryResult.builder()
                .mode(mode)
                .status(DeliveryOutcome.DISPATCHED)
                .build();
    }

    public static DeliveryResult failed(String mode, String errorDetail) {
        return DeliveryResult.builder()
                .mode(mode)
                .status(DeliveryOutcome.FAILED)
                .error(errorDetail)
                .build();
    }
}
