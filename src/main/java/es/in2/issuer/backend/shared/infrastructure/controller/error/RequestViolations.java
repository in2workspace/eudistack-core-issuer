package es.in2.issuer.backend.shared.infrastructure.controller.error;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonMappingException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebInputException;

import java.util.List;
import java.util.stream.Collectors;

/**
 * The field violations of a request body that cannot be read or does not pass validation (EUD-254
 * contract: every {@code BAD_REQUEST} on the shape or format of a field carries {@code violations}).
 * Fields are named as the client sent them -- the JSON name ({@code credential_configuration_id}),
 * never the Java one ({@code credentialConfigurationId}).
 */
public final class RequestViolations {

    /** Reason of a field the body could not be read into: absent when required, or of the wrong type. */
    static final String UNREADABLE_FIELD = "is missing or has an invalid format";
    static final String INVALID_FIELD = "is not valid";

    private RequestViolations() {
    }

    /** One violation per field that failed Bean Validation, with the constraint's message. */
    public static List<GlobalErrorMessage.FieldViolation> of(WebExchangeBindException ex) {
        Object target = ex.getBindingResult().getTarget();
        Class<?> type = target != null ? target.getClass() : null;
        return ex.getBindingResult().getFieldErrors().stream()
                .map(error -> new GlobalErrorMessage.FieldViolation(jsonName(type, error), message(error)))
                .toList();
    }

    /**
     * The field Jackson could not read the body into, when the body is JSON but a field is missing
     * or of the wrong type. Empty when the body is not JSON at all, or for any other input error.
     */
    public static List<GlobalErrorMessage.FieldViolation> of(ServerWebInputException ex) {
        JsonMappingException mapping = findCause(ex);
        if (mapping == null || mapping.getPath().isEmpty()) {
            return List.of();
        }
        String field = mapping.getPath().stream()
                .map(reference -> reference.getFieldName() != null
                        ? reference.getFieldName() : "[" + reference.getIndex() + "]")
                .collect(Collectors.joining("."))
                .replace(".[", "[");
        return List.of(new GlobalErrorMessage.FieldViolation(field, UNREADABLE_FIELD));
    }

    private static String message(FieldError error) {
        String message = error.getDefaultMessage();
        return message == null || message.isBlank() ? INVALID_FIELD : message;
    }

    /** The JSON name of the first path segment, from its {@code @JsonProperty}; the rest is kept. */
    private static String jsonName(Class<?> type, FieldError error) {
        String path = error.getField();
        int dot = path.indexOf('.');
        String head = dot < 0 ? path : path.substring(0, dot);
        String tail = dot < 0 ? "" : path.substring(dot);
        return renamed(type, head) + tail;
    }

    private static String renamed(Class<?> type, String field) {
        if (type == null) {
            return field;
        }
        try {
            JsonProperty property = type.getDeclaredField(field).getAnnotation(JsonProperty.class);
            return property != null && !property.value().isEmpty() ? property.value() : field;
        } catch (NoSuchFieldException _) {
            return field;
        }
    }

    private static JsonMappingException findCause(Throwable ex) {
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
            if (cause instanceof JsonMappingException mapping) {
                return mapping;
            }
        }
        return null;
    }
}
