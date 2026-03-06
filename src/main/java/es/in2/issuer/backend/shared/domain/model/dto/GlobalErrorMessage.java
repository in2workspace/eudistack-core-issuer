package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

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
        @JsonProperty("c_nonce_expires_in") Long cNonceExpiresIn
) {
    public GlobalErrorMessage(String type, String title, int status, String detail, String instance) {
        this(type, title, status, detail, instance, null, null, null);
    }

    public GlobalErrorMessage(String type, String title, int status, String detail, String instance,
                              List<FieldViolation> violations) {
        this(type, title, status, detail, instance, violations, null, null);
    }

    public GlobalErrorMessage withNonce(String cNonce, long cNonceExpiresIn) {
        return new GlobalErrorMessage(type, title, status, detail, instance, violations, cNonce, cNonceExpiresIn);
    }

    public record FieldViolation(String field, String message) {}
}
