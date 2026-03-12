package es.in2.issuer.backend.statuslist.domain.model;

import java.util.Locale;

/**
 * Discriminates how a status list is serialized and served:
 * - BITSTRING_VC: W3C BitstringStatusListCredential (application/vc+jwt)
 * - TOKEN_JWT: draft-ietf-oauth-status-list Token Status List (application/statuslist+jwt)
 */
public enum StatusListFormat {

    BITSTRING_VC("bitstring_vc"),
    TOKEN_JWT("token_jwt");

    private final String value;

    StatusListFormat(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static StatusListFormat fromValue(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("StatusListFormat cannot be null");
        }
        String normalized = raw.trim().toLowerCase(Locale.ROOT);
        for (StatusListFormat f : values()) {
            if (f.value.equals(normalized)) {
                return f;
            }
        }
        throw new IllegalArgumentException("Unsupported StatusListFormat: " + raw);
    }
}
