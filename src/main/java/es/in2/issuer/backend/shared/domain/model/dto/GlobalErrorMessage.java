package es.in2.issuer.backend.shared.domain.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record GlobalErrorMessage(
        String type,
        String title,
        int status,
        String detail,
        String instance,
        List<FieldViolation> violations
) {
    public GlobalErrorMessage(String type, String title, int status, String detail, String instance) {
        this(type, title, status, detail, instance, null);
    }

    public record FieldViolation(String field, String message) {}
}
