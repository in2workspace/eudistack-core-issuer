package es.in2.issuer.backend.shared.domain.model.catalog;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Path to an attribute of an attestation, as in OID4VCI {@code claims.path} (for example
 * {@code [mandate, mandatee, firstName]}). Only string segments are supported.
 *
 * <p>A blank segment is a string, so it is a well-formed path (the contract's {@code ClaimPath} has no
 * {@code minLength}); it just points at no attribute, which is for the schema check to reject (A12).
 */
public record ClaimPath(List<String> segments) {

    public ClaimPath {
        Objects.requireNonNull(segments, "segments");
        if (segments.isEmpty()) {
            throw new IllegalArgumentException("A claim path needs at least one segment");
        }
        if (segments.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("A claim path segment must be a string");
        }
        segments = List.copyOf(segments);
    }

    public static ClaimPath of(String... segments) {
        return new ClaimPath(List.of(segments));
    }

    /** {@code [mandate, mandatee, firstName]}; a blank segment is quoted, so {@code [""]} does not read as {@code []}. */
    @Override
    public String toString() {
        return segments.stream()
                .map(s -> s.isBlank() ? "\"" + s + "\"" : s)
                .collect(Collectors.joining(", ", "[", "]"));
    }
}
