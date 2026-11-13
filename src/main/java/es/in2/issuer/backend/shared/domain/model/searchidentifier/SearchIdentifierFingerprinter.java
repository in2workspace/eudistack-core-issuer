package es.in2.issuer.backend.shared.domain.model.searchidentifier;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * The single fingerprint component of the issuer (EUD-267; AD-3 of the EUD-254 design, AD-4 of the EUD-255
 * design): the issuance uses it to store the fingerprints of a process, and the query API to search by an
 * identifier, so the same value always gives the same fingerprint.
 *
 * <ul>
 *   <li><b>Normalization</b> (§5 of the EUD-254 PRD, the rule the client is told): every whitespace character is
 *       removed, interior ones too, and the rest is upper-cased with {@link Locale#ROOT}. Every other character is
 *       kept, such as the slash of {@code 28/12345}.</li>
 *   <li><b>Fingerprint</b>: HMAC-SHA256 of the normalized value (UTF-8) with the tenant's secret key. A blind
 *       index: it is never decrypted, and without the key it does not allow finding the value or testing
 *       possible ones. A value that normalizes to nothing has no fingerprint.</li>
 * </ul>
 *
 * <p>Pure domain code, without framework: no I/O, no logging of values.
 */
public final class SearchIdentifierFingerprinter {

    /** Length of a fingerprint and the minimum length of a tenant key. */
    public static final int FINGERPRINT_BYTES = 32;

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final byte[] KEY_ID_LABEL = "eudistack-search-identifier-key-id".getBytes(StandardCharsets.UTF_8);
    /** Bytes of the key id: enough to tell a rotated key apart, too few to say anything about the key. */
    private static final int KEY_ID_BYTES = 8;

    private SearchIdentifierFingerprinter() {
    }

    /** The value as it is fingerprinted: without whitespace, in upper case. {@code null} gives the empty string. */
    public static String normalize(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder normalized = new StringBuilder(value.length());
        value.codePoints()
                .filter(codePoint -> !Character.isWhitespace(codePoint) && !Character.isSpaceChar(codePoint))
                .forEach(normalized::appendCodePoint);
        return normalized.toString().toUpperCase(Locale.ROOT);
    }

    /** The fingerprint of a value; empty when the value is missing or normalizes to nothing. */
    public static Optional<byte[]> fingerprint(byte[] tenantKey, String value) {
        String normalized = normalize(value);
        if (normalized.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(hmac(requireKey(tenantKey), normalized.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * The fingerprints of an attestation: one per identifier the catalog entry declares and the attestation
     * contains, read from the attestation as built (the paths are resolved as for the subject of the entry, so
     * the stored data of a process gives the same result). An identifier whose attribute is missing, empty or
     * not a text or a number has no fingerprint. When two identifiers of the entry share a name, the first one
     * that has a value is the one kept: a process has at most one fingerprint per name.
     */
    public static List<SearchIdentifierFingerprint> fingerprintsOf(byte[] tenantKey,
                                                                   List<CatalogEntry.SearchIdentifier> identifiers,
                                                                   JsonNode attestation) {
        List<SearchIdentifierFingerprint> fingerprints = new ArrayList<>();
        Set<String> names = new HashSet<>();
        for (CatalogEntry.SearchIdentifier identifier : identifiers) {
            if (names.contains(identifier.name())) {
                continue;
            }
            valueAt(attestation, identifier.field())
                    .flatMap(value -> fingerprint(tenantKey, value))
                    .ifPresent(fingerprint -> {
                        names.add(identifier.name());
                        fingerprints.add(new SearchIdentifierFingerprint(identifier.name(), fingerprint));
                    });
        }
        return List.copyOf(fingerprints);
    }

    /**
     * Identifies a tenant key without revealing it: the first bytes of an HMAC of a fixed label, in hex. Stored
     * with what was indexed, so a rotated key is noticed and the fingerprints computed again.
     */
    public static String keyId(byte[] tenantKey) {
        byte[] mac = hmac(requireKey(tenantKey), KEY_ID_LABEL);
        return HexFormat.of().formatHex(mac, 0, KEY_ID_BYTES);
    }

    /** A text or a number at the path; empty otherwise. */
    static Optional<String> valueAt(JsonNode root, ClaimPath path) {
        JsonNode current = root;
        for (String segment : path.segments()) {
            if (current == null || !current.isObject() || !current.has(segment)) {
                return Optional.empty();
            }
            current = current.get(segment);
        }
        if (current == null || !(current.isTextual() || current.isNumber())) {
            return Optional.empty();
        }
        return Optional.of(current.asText());
    }

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }

    private static byte[] requireKey(byte[] tenantKey) {
        if (tenantKey == null || tenantKey.length < FINGERPRINT_BYTES) {
            throw new IllegalArgumentException("A tenant key needs at least " + FINGERPRINT_BYTES + " bytes");
        }
        return tenantKey;
    }
}
