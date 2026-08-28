package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;

class RecipientPseudonymizerTest {

    private final RecipientPseudonymizer pseudonymizer = new RecipientPseudonymizer();

    @Test
    void hash_withSameTenantAndValue_isDeterministic() {
        // Given
        String raw = "holder@example.com";

        // When
        String first = pseudonymizer.hash("sandbox", raw);
        String second = pseudonymizer.hash("sandbox", raw);

        // Then
        assertEquals(first, second);
    }

    @Test
    void hash_neverReturnsTheRawValue() {
        // Given
        String raw = "holder@example.com";

        // When
        String hashed = pseudonymizer.hash("sandbox", raw);

        // Then
        assertNotEquals(raw, hashed);
        assertFalse(hashed.contains(raw));
    }

    @Test
    void hash_withSameValueDifferentTenant_producesDifferentHash() {
        // Given
        String raw = "holder@example.com";

        // When
        String sandboxHash = pseudonymizer.hash("sandbox", raw);
        String kpmgHash = pseudonymizer.hash("kpmg", raw);

        // Then (NFR-S-02: no cross-tenant correlation)
        assertNotEquals(sandboxHash, kpmgHash);
    }

    @Test
    void hash_withBlankTenantId_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pseudonymizer.hash(" ", "holder@example.com"));
    }

    @Test
    void hash_withNullRawValue_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pseudonymizer.hash("sandbox", null));
    }

    @Test
    void hash_withBlankRawValue_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> pseudonymizer.hash("sandbox", " "));
    }
}
