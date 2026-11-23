package es.in2.issuer.backend.shared.domain.model.searchidentifier;

import java.util.Arrays;
import java.util.Objects;

/**
 * The fingerprint of one search identifier of an issuance process (EUD-267, FR-11 of EUD-254): the name the
 * catalog entry gives the identifier and the HMAC-SHA256 of its normalized value with the tenant key. The value
 * is never kept, and the fingerprint is never printed: it leaves the issuer in no response and in no trace.
 *
 * @param identifierType the name of the identifier in the catalog entry, for example {@code dni}
 * @param fingerprint    32 bytes
 */
public record SearchIdentifierFingerprint(String identifierType, byte[] fingerprint) {

    public SearchIdentifierFingerprint {
        Objects.requireNonNull(identifierType, "identifierType");
        Objects.requireNonNull(fingerprint, "fingerprint");
        if (fingerprint.length != SearchIdentifierFingerprinter.FINGERPRINT_BYTES) {
            throw new IllegalArgumentException("A fingerprint has " + SearchIdentifierFingerprinter.FINGERPRINT_BYTES
                    + " bytes");
        }
        fingerprint = fingerprint.clone();
    }

    @Override
    public byte[] fingerprint() {
        return fingerprint.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof SearchIdentifierFingerprint(String thatType, byte[] thatFingerprint)
                && identifierType.equals(thatType)
                && Arrays.equals(fingerprint, thatFingerprint);
    }

    @Override
    public int hashCode() {
        return 31 * identifierType.hashCode() + Arrays.hashCode(fingerprint);
    }

    /** The fingerprint is never printed. */
    @Override
    public String toString() {
        return "SearchIdentifierFingerprint[identifierType=" + identifierType + ", fingerprint=redacted]";
    }
}
