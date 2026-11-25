package es.in2.issuer.backend.shared.domain.model.query;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * The search by a business identifier (EUD-255 FR-05, AD-4 and AD-5): its type, a name of search identifier that the
 * catalogue of the tenant declares, and either the value as the request gave it or, once the use case has computed
 * it with the tenant key, its fingerprint. From then on only the fingerprint goes on: the value in clear reaches the
 * trace of the query and nothing else (the persistence, the cursor, the logs).
 *
 * @param type        the name of the identifier ({@code colegiado}, {@code dni}...)
 * @param value       the value as received; {@code null} once fingerprinted
 * @param fingerprint the fingerprint of the value with the tenant key; {@code null} until it is computed, empty when
 *                    the value normalizes to nothing (it then matches no process)
 */
public record SearchIdentifierCriterion(String type, String value, byte[] fingerprint) {

    public SearchIdentifierCriterion {
        Objects.requireNonNull(type, "type");
        if ((value == null) == (fingerprint == null)) {
            throw new IllegalArgumentException("A search identifier has either its value or its fingerprint");
        }
        fingerprint = fingerprint == null ? null : fingerprint.clone();
    }

    /** The search as received, before the fingerprint. */
    public static SearchIdentifierCriterion searched(String type, String value) {
        return new SearchIdentifierCriterion(type, Objects.requireNonNull(value, "value"), null);
    }

    /** The same search by its fingerprint, without the value. */
    public SearchIdentifierCriterion fingerprinted(byte[] computed) {
        return new SearchIdentifierCriterion(type, null, Objects.requireNonNull(computed, "fingerprint"));
    }

    public boolean isFingerprinted() {
        return fingerprint != null;
    }

    @Override
    public byte[] fingerprint() {
        return fingerprint == null ? null : fingerprint.clone();
    }

    /** The fingerprint in base64url, for the digest of the filters of a cursor. */
    String fingerprintText() {
        if (fingerprint == null) {
            throw new IllegalStateException("The search identifier has not been fingerprinted yet");
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(fingerprint);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SearchIdentifierCriterion(String otherType, String otherValue, byte[] otherFingerprint)
                && type.equals(otherType)
                && Objects.equals(value, otherValue)
                && Arrays.equals(fingerprint, otherFingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, value, Arrays.hashCode(fingerprint));
    }

    /** Neither the value nor the fingerprint: the value is personal data (AD-5). */
    @Override
    public String toString() {
        return "SearchIdentifierCriterion[type=" + type + ", " + (isFingerprinted() ? "fingerprinted" : "<redacted>") + "]";
    }
}
