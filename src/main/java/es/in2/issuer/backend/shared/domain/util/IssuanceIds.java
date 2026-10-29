package es.in2.issuer.backend.shared.domain.util;

import java.util.Optional;
import java.util.UUID;

/**
 * Reads the issuance id a client sent (EUD-307). Only the canonical UUID form is an id:
 * {@link UUID#fromString} also accepts shortened forms such as {@code 1-1-1-1-1}, which are rejected here.
 */
public final class IssuanceIds {

    private IssuanceIds() {
    }

    public static Optional<UUID> parse(String id) {
        if (id == null) {
            return Optional.empty();
        }
        try {
            UUID uuid = UUID.fromString(id);
            return uuid.toString().equalsIgnoreCase(id) ? Optional.of(uuid) : Optional.empty();
        } catch (IllegalArgumentException _) {
            return Optional.empty();
        }
    }
}
