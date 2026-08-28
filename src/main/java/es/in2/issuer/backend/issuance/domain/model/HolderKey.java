package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.core.JsonProcessingException;
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

    /**
     * Parses a {@code holder_key} JSON node into a {@link HolderKey}.
     *
     * <p>Required for every delivery mode of a credential type that requires holder binding but
     * declares no {@code cryptographic_binding_methods_supported} (EUD-33): no wallet proof will
     * arrive for such a type, so the request is the only source of the holder key.
     */
    public static HolderKey fromJson(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            throw new InvalidHolderKeyException(
                    "holder_key is required for a credential type requiring holder binding "
                            + "with no cryptographic binding method");
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

    /**
     * Serializes the normalized cnf for persistence, so the OID4VCI credential endpoint -- a separate
     * HTTP call, later in time -- reads it back without re-validating its shape (EUD-33).
     *
     * <p>Paired with {@link #fromJson(JsonNode)} on purpose: validation and serialization of a holder
     * key belong to the holder key, not to the workflow that happens to handle it.
     */
    public String toJson() {
        try {
            return OBJECT_MAPPER.writeValueAsString(cnf);
        } catch (JsonProcessingException e) {
            // Unreachable in practice: cnf was built from a parsed JsonNode. Fail closed anyway rather
            // than persist an issuance whose holder binding cannot be recovered. Carries no key material.
            throw new IllegalStateException("Failed to serialize holder cnf", e);
        }
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
