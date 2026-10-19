package es.in2.issuer.backend.shared.domain.model.catalog;

import java.util.List;
import java.util.Objects;

/**
 * Path to an attribute of an attestation, as in OID4VCI {@code claims.path} (for example
 * {@code [mandate, mandatee, firstName]}). Only string segments are supported.
 */
public record ClaimPath(List<String> segments) {

    public ClaimPath {
        Objects.requireNonNull(segments, "segments");
        if (segments.isEmpty()) {
            throw new IllegalArgumentException("A claim path needs at least one segment");
        }
        if (segments.stream().anyMatch(s -> s == null || s.isBlank())) {
            throw new IllegalArgumentException("A claim path segment must not be blank");
        }
        segments = List.copyOf(segments);
    }

    public static ClaimPath of(String... segments) {
        return new ClaimPath(List.of(segments));
    }

    @Override
    public String toString() {
        return segments.toString();
    }
}
