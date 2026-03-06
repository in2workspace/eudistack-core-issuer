package es.in2.issuer.backend.statuslist.domain.factory;

import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;

import java.time.Instant;
import java.util.Map;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.TOKEN_STATUS_LIST_ENTRY_TYPE;
import static org.junit.jupiter.api.Assertions.*;

class TokenStatusListCredentialFactoryTest {

    private final TokenStatusListCredentialFactory factory = new TokenStatusListCredentialFactory();

    // -------------------- buildUnsigned --------------------

    @Test
    void buildUnsigned_returnsCorrectPayloadStructure() {
        String listUrl = "https://issuer.example/token/v1/credentials/status/42";
        String issuerId = "did:elsi:VATES-12345678A";
        String purpose = "revocation";
        String encodedList = "uABCDEF123";

        Map<String, Object> payload = factory.buildUnsigned(listUrl, issuerId, purpose, encodedList);

        assertEquals(listUrl, payload.get("sub"));
        assertEquals(issuerId, payload.get("iss"));
        assertNotNull(payload.get("iat"));
        assertNotNull(payload.get("exp"));

        long iat = (long) payload.get("iat");
        long exp = (long) payload.get("exp");
        assertTrue(exp > iat, "exp should be after iat");
        // Default lifetime is 365 days
        long diff = exp - iat;
        assertTrue(diff >= 364 * 86400 && diff <= 366 * 86400, "Should be approximately 365 days");

        @SuppressWarnings("unchecked")
        Map<String, Object> statusList = (Map<String, Object>) payload.get("status_list");
        assertNotNull(statusList);
        assertEquals(1, statusList.get("bits"));
        // Should strip the 'u' multibase prefix
        assertEquals("ABCDEF123", statusList.get("lst"));
    }

    @Test
    void buildUnsigned_doesNotStripWhenNoMultibasePrefix() {
        Map<String, Object> payload = factory.buildUnsigned(
                "https://example.com/status/1", "did:example:1", "revocation", "ABCDEF");

        @SuppressWarnings("unchecked")
        Map<String, Object> statusList = (Map<String, Object>) payload.get("status_list");
        assertEquals("ABCDEF", statusList.get("lst"));
    }

    @Test
    void buildUnsigned_iatIsCloseToNow() {
        Map<String, Object> payload = factory.buildUnsigned(
                "https://example.com/status/1", "did:example:1", "revocation", "uXYZ");

        long iat = (long) payload.get("iat");
        long nowEpoch = Instant.now().getEpochSecond();
        assertTrue(Math.abs(nowEpoch - iat) < 5, "iat should be close to now");
    }

    @ParameterizedTest
    @NullSource
    void buildUnsigned_nullListUrl_throws(String listUrl) {
        assertThrows(NullPointerException.class,
                () -> factory.buildUnsigned(listUrl, "iss", "purpose", "encoded"));
    }

    @ParameterizedTest
    @NullSource
    void buildUnsigned_nullIssuerId_throws(String issuerId) {
        assertThrows(NullPointerException.class,
                () -> factory.buildUnsigned("url", issuerId, "purpose", "encoded"));
    }

    @ParameterizedTest
    @NullSource
    void buildUnsigned_nullPurpose_throws(String purpose) {
        assertThrows(NullPointerException.class,
                () -> factory.buildUnsigned("url", "iss", purpose, "encoded"));
    }

    @ParameterizedTest
    @NullSource
    void buildUnsigned_nullEncodedList_throws(String encodedList) {
        assertThrows(NullPointerException.class,
                () -> factory.buildUnsigned("url", "iss", "purpose", encodedList));
    }

    // -------------------- buildStatusListEntry --------------------

    @Test
    void buildStatusListEntry_returnsCorrectEntry() {
        String listUrl = "https://issuer.example/token/v1/credentials/status/55";
        int idx = 42;
        StatusPurpose purpose = StatusPurpose.REVOCATION;

        StatusListEntry entry = factory.buildStatusListEntry(listUrl, idx, purpose);

        assertEquals(listUrl + "#42", entry.id());
        assertEquals(TOKEN_STATUS_LIST_ENTRY_TYPE, entry.type());
        assertEquals(purpose, entry.statusPurpose());
        assertEquals("42", entry.statusListIndex());
        assertEquals(listUrl, entry.statusListCredential());
    }

    @Test
    void buildStatusListEntry_nullListUrl_throws() {
        assertThrows(NullPointerException.class,
                () -> factory.buildStatusListEntry(null, 0, StatusPurpose.REVOCATION));
    }

    @Test
    void buildStatusListEntry_nullIdx_throws() {
        assertThrows(NullPointerException.class,
                () -> factory.buildStatusListEntry("url", null, StatusPurpose.REVOCATION));
    }

    @Test
    void buildStatusListEntry_nullPurpose_throws() {
        assertThrows(NullPointerException.class,
                () -> factory.buildStatusListEntry("url", 0, null));
    }
}
