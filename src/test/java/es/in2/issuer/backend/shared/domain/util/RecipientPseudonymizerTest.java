package es.in2.issuer.backend.shared.domain.util;

import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprinter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RecipientPseudonymizerTest {

    private static final byte[] SANDBOX_KEY = "sandbox-secret-key-of-32-bytes!!".getBytes(StandardCharsets.UTF_8);
    private static final byte[] KPMG_KEY = "kpmg-secret-key-of-32-bytes-....".getBytes(StandardCharsets.UTF_8);

    private final RecipientPseudonymizer pseudonymizer = new RecipientPseudonymizer();

    @Test
    void hash_withSameKeyAndValue_isDeterministic() {
        String raw = "holder@example.com";

        assertEquals(pseudonymizer.hash(SANDBOX_KEY, raw), pseudonymizer.hash(SANDBOX_KEY, raw));
    }

    @Test
    void hash_neverReturnsTheRawValue() {
        String raw = "holder@example.com";

        String hashed = pseudonymizer.hash(SANDBOX_KEY, raw);

        assertNotEquals(raw, hashed);
        assertFalse(hashed.contains(raw));
    }

    @Test
    void hash_withSameValueAnotherTenantKey_producesDifferentHash() {
        String raw = "holder@example.com";

        // NFR-S-02: no cross-tenant correlation.
        assertNotEquals(pseudonymizer.hash(SANDBOX_KEY, raw), pseudonymizer.hash(KPMG_KEY, raw));
    }

    @Test
    void hash_isNotTheSearchIdentifierFingerprintOfTheSameValue() {
        // TD-20 of EUD-254: the same tenant key, but a key of its own for the pseudonyms.
        String raw = "HOLDER@EXAMPLE.COM";
        String fingerprint = HexFormat.of().formatHex(SearchIdentifierFingerprinter.fingerprint(SANDBOX_KEY, raw).orElseThrow());

        assertNotEquals(fingerprint, pseudonymizer.hash(SANDBOX_KEY, raw));
    }

    @Test
    void hash_withoutTheTenantSecretKey_throwsIllegalArgumentException() {
        byte[] tooShort = "tenant-id".getBytes(StandardCharsets.UTF_8);

        assertThrows(IllegalArgumentException.class, () -> pseudonymizer.hash(null, "holder@example.com"));
        assertThrows(IllegalArgumentException.class, () -> pseudonymizer.hash(tooShort, "holder@example.com"));
    }

    @Test
    void hash_withNullRawValue_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pseudonymizer.hash(SANDBOX_KEY, null));
    }

    @Test
    void hash_withBlankRawValue_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pseudonymizer.hash(SANDBOX_KEY, " "));
    }
}
