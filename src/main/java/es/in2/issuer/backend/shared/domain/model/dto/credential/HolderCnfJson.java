package es.in2.issuer.backend.shared.domain.model.dto.credential;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

/**
 * Codec for the {@code cnf} claim as persisted on the {@code issuance} row (EUD-168 AD-8).
 *
 * <p>The credential types exempt from ADR-110 declare no {@code proof_types_supported}, so their
 * holder key arrives once — in the issuance request — and is needed again in a later request, at the
 * OID4VCI Credential Endpoint, where no key proof will arrive to replace it. The signing path speaks
 * in {@code Map<String, Object>}; the row stores text. This translates between the two, in one place,
 * so neither workflow needs an {@link ObjectMapper} of its own for a single field.
 */
public final class HolderCnfJson {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private HolderCnfJson() {
    }

    /** {@code null} for an absent or empty cnf, so the column stays unset for non-exempt types. */
    public static String write(Map<String, Object> cnf) {
        if (cnf == null || cnf.isEmpty()) {
            return null;
        }
        try {
            return OBJECT_MAPPER.writeValueAsString(cnf);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize holder cnf", e);
        }
    }

    /** Empty map for an absent value, so callers can fall back to the key-proof binding. */
    public static Map<String, Object> read(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return OBJECT_MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize holder cnf", e);
        }
    }
}
