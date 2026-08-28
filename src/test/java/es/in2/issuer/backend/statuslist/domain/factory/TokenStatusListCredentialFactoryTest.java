package es.in2.issuer.backend.statuslist.domain.factory;

import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import es.in2.issuer.backend.statuslist.domain.util.BitstringEncoder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import static es.in2.issuer.backend.statuslist.domain.util.Constants.TOKEN_STATUS_LIST_ENTRY_TYPE;
import static org.junit.jupiter.api.Assertions.*;

class TokenStatusListCredentialFactoryTest {

    private final TokenStatusListCredentialFactory factory = new TokenStatusListCredentialFactory();
    private final BitstringEncoder bitstringEncoder = new BitstringEncoder();

    /** Undoes deflateRaw: raw-DEFLATE-inflate (nowrap=true) + base64url-decode, mirroring a spec-conformant reader. */
    private byte[] inflateRawBase64url(String lst) throws DataFormatException {
        byte[] compressed = Base64.getUrlDecoder().decode(lst);
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(compressed);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            while (!inflater.finished()) {
                int n = inflater.inflate(buffer);
                if (n == 0 && inflater.needsInput()) break;
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } finally {
            inflater.end();
        }
    }

    // -------------------- buildUnsigned --------------------

    @Test
    void buildUnsigned_returnsCorrectPayloadStructure() throws DataFormatException {
        String listUrl = "https://issuer.example/token/v1/credentials/status/42";
        String issuerId = "did:elsi:VATES-12345678A";
        String purpose = "revocation";
        byte[] rawBits = new byte[]{(byte) 0b10100000};
        String encodedList = bitstringEncoder.encode(rawBits);

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
        // Regression test: draft-ietf-oauth-status-list requires raw DEFLATE (RFC 1951) for
        // `lst`, not the GZIP (RFC 1952) that encodedList's own storage format uses - passing
        // the GZIP bytes straight through used to produce an `lst` conformant readers couldn't
        // inflate ("incorrect header check"). `lst` must be raw-DEFLATE-decodable back to the
        // original bitstring bytes.
        String lst = (String) statusList.get("lst");
        assertFalse(lst.startsWith("u"), "lst must not carry the multibase prefix");
        assertArrayEquals(rawBits, inflateRawBase64url(lst));
    }

    @Test
    void buildUnsigned_decodesEncodedListWithoutMultibasePrefix() throws DataFormatException {
        byte[] rawBits = new byte[]{0x00, (byte) 0xFF};
        String encodedListNoPrefix = bitstringEncoder.encode(rawBits).substring(1); // strip 'u'

        Map<String, Object> payload = factory.buildUnsigned(
                "https://example.com/status/1", "did:example:1", "revocation", encodedListNoPrefix);

        @SuppressWarnings("unchecked")
        Map<String, Object> statusList = (Map<String, Object>) payload.get("status_list");
        assertArrayEquals(rawBits, inflateRawBase64url((String) statusList.get("lst")));
    }

    @Test
    void buildUnsigned_iatIsCloseToNow() {
        String encodedList = bitstringEncoder.createEmptyEncodedList(8);
        Map<String, Object> payload = factory.buildUnsigned(
                "https://example.com/status/1", "did:example:1", "revocation", encodedList);

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
