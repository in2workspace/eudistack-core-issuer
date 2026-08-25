package es.in2.issuer.backend.shared.infrastructure.controller.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record GlobalErrorMessage(
        String type,
        String title,
        int status,
        String detail,
        String instance,
        List<FieldViolation> violations,
        @JsonProperty("c_nonce") String cNonce,
        @JsonProperty("c_nonce_expires_in") Long cNonceExpiresIn,
        /**
         * Per-mode delivery outcome, on the error side of the same contract the success body uses
         * (EUD-33 AC-06). Present only for delivery failures; {@code NON_NULL} keeps every other
         * error body byte-identical to before.
         */
        @JsonProperty("delivery_results") List<DeliveryResult> deliveryResults
) {
    public GlobalErrorMessage(String type, String title, int status, String detail, String instance) {
        this(type, title, status, detail, instance, null, null, null, null);
    }

    public GlobalErrorMessage(String type, String title, int status, String detail, String instance,
                              List<FieldViolation> violations) {
        this(type, title, status, detail, instance, violations, null, null, null);
    }

    public GlobalErrorMessage withNonce(String cNonce, long cNonceExpiresIn) {
        return new GlobalErrorMessage(type, title, status, detail, instance, violations,
                cNonce, cNonceExpiresIn, deliveryResults);
    }

    public GlobalErrorMessage withDeliveryResults(List<DeliveryResult> deliveryResults) {
        List<DeliveryResult> results = (deliveryResults == null || deliveryResults.isEmpty())
                ? null : List.copyOf(deliveryResults);
        return new GlobalErrorMessage(type, title, status, detail, instance, violations,
                cNonce, cNonceExpiresIn, results);
    }

    public record FieldViolation(String field, String message) {}
}
