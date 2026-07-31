package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;

import java.util.List;
import java.util.Map;
import java.util.Objects;

public record HolderKey(Map<String, Object> cnf) {

    private static final List<String> CNF_FORMS = List.of("jwk", "kid", "x5c");
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public HolderKey {
        Objects.requireNonNull(cnf, "cnf");
    }

    /** Parses a {@code holder_key} JSON node into a {@link HolderKey}.*/
    public static HolderKey fromJson(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            throw new InvalidHolderKeyException(
                    "holder_key is required for direct delivery of a credential type requiring holder binding");
        }
        if (!node.isObject()) {
            throw new InvalidHolderKeyException("invalid holder_key: expected a JSON object");
        }

        String presentForm = null;
        for (String form : CNF_FORMS) {
            JsonNode value = node.get(form);
            if (value != null && !value.isNull()) {
                if (presentForm != null) {
                    throw new InvalidHolderKeyException(
                            "invalid holder_key: expected exactly one of jwk/kid/x5c");
                }
                presentForm = form;
            }
        }
        if (presentForm == null) {
            throw new InvalidHolderKeyException(
                    "invalid holder_key: expected exactly one of jwk/kid/x5c");
        }

        JsonNode valueNode = node.get(presentForm);
        validateFormShape(presentForm, valueNode);

        Object value = OBJECT_MAPPER.convertValue(valueNode, Object.class);
        return new HolderKey(Map.of(presentForm, value));
    }

    private static void validateFormShape(String form, JsonNode value) {
        switch (form) {
            case "jwk" -> {
                if (!value.isObject() || value.isEmpty()) {
                    throw new InvalidHolderKeyException("invalid holder_key: jwk must be a non-empty JSON object");
                }
            }
            case "kid" -> {
                if (!value.isTextual() || value.asText().isBlank()) {
                    throw new InvalidHolderKeyException("invalid holder_key: kid must be a non-blank string");
                }
            }
            case "x5c" -> {
                if (!value.isArray() || value.isEmpty()) {
                    throw new InvalidHolderKeyException(
                            "invalid holder_key: x5c must be a non-empty array of certificate strings");
                }
                for (JsonNode cert : value) {
                    if (!cert.isTextual() || cert.asText().isBlank()) {
                        throw new InvalidHolderKeyException("invalid holder_key: x5c entries must be non-blank strings");
                    }
                }
            }
            default -> throw new InvalidHolderKeyException("invalid holder_key: unsupported confirmation form " + form);
        }
    }
}
