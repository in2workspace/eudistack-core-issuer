package es.in2.issuer.backend.issuance.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HolderKeyTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String raw) {
        try {
            return MAPPER.readTree(raw);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // A real P-256 public point: Nimbus validates x/y are actually on the declared curve, so an
    // arbitrary placeholder string is not a valid fixture here.
    private static final String VALID_EC_X = "jIoYu_tVQYeSX_WAXLz219rFkqGV6c4FTb4_cQdOaQg";
    private static final String VALID_EC_Y = "BBkUW2sUZX2kW7keQ-qZV3PCKCLOZesPpszoNGciDL4";

    @Test
    void fromJson_withJwk_returnsCnfCarryingJwkObject() {
        // Given
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + VALID_EC_X + "\",\"y\":\"" + VALID_EC_Y + "\"}}");

        // When
        Map<String, Object> cnf = HolderKey.fromJson(node).cnf();

        // Then
        assertEquals(1, cnf.size());
        assertTrue(cnf.containsKey("jwk"));
        assertInstanceOf(Map.class, cnf.get("jwk"));
        assertEquals("EC", ((Map<?, ?>) cnf.get("jwk")).get("kty"));
    }

    @Test
    void fromJson_withKid_returnsCnfCarryingKidString() {
        // Given
        JsonNode node = json("{\"kid\":\"did:key:z6Mk#key-1\"}");

        // When
        Map<String, Object> cnf = HolderKey.fromJson(node).cnf();

        // Then
        assertEquals(Map.of("kid", "did:key:z6Mk#key-1"), cnf);
    }

    @Test
    void fromJson_withX5c_returnsCnfCarryingX5cArray() {
        // Given
        JsonNode node = json("{\"x5c\":[\"MIIBcert1\",\"MIIBcert2\"]}");

        // When
        Map<String, Object> cnf = HolderKey.fromJson(node).cnf();

        // Then
        assertEquals(1, cnf.size());
        assertEquals(List.of("MIIBcert1", "MIIBcert2"), cnf.get("x5c"));
    }

    @Test
    void fromJson_withJavaNull_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(null));
    }

    @Test
    void fromJson_withNullNode_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(NullNode.getInstance()));
    }

    @Test
    void fromJson_withEmptyObject_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{}")));
    }

    @Test
    void fromJson_withTwoForms_throwsInvalidHolderKey() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\"},\"kid\":\"did:key:z6Mk#key-1\"}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    @Test
    void fromJson_withAllThreeForms_throwsInvalidHolderKey() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\"},\"kid\":\"k\",\"x5c\":[\"c\"]}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    @Test
    void fromJson_withNonObjectNode_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("\"just-a-string\"")));
    }

    @Test
    void fromJson_withUnrelatedKeysOnly_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"foo\":\"bar\"}")));
    }

    // --- Per-form shape validation (RFC 7800) ---

    @Test
    void fromJson_withKidAsObject_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"kid\":{\"x\":1}}")));
    }

    @Test
    void fromJson_withBlankKid_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"kid\":\"  \"}")));
    }

    @Test
    void fromJson_withJwkNotObject_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"jwk\":\"not-an-object\"}")));
    }

    @Test
    void fromJson_withEmptyJwkObject_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"jwk\":{}}")));
    }

    @Test
    void fromJson_withEmptyX5cArray_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"x5c\":[]}")));
    }

    @Test
    void fromJson_withX5cContainingNonStringEntry_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"x5c\":[\"MIIBcert\",123]}")));
    }

    @Test
    void fromJson_withX5cContainingBlankEntry_throwsInvalidHolderKey() {
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(json("{\"x5c\":[\"MIIBcert\",\"\"]}")));
    }

    // --- Nimbus JWK content validation (EUD-168 F1, S1) ---

    @Test
    void fromJson_withPrivateEcJwk_throwsInvalidHolderKey() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + VALID_EC_X + "\",\"y\":\"" + VALID_EC_Y
                + "\",\"d\":\"PtiOr4fsLlHZ2QdHKcO2HoslwwlEXka6_ksM1fSDTdg\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    @Test
    void fromJson_withOctJwk_throwsInvalidHolderKey() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"oct\",\"k\":\"c2VjcmV0\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    @Test
    void fromJson_withUnrecognizedKty_throwsInvalidHolderKey() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"unsupported\",\"x\":\"abc\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    @Test
    void fromJson_withUnsupportedEcCurve_throwsInvalidHolderKey() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"secp256k1\",\"x\":\"abc\",\"y\":\"def\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    @Test
    void fromJson_withUndersizedRsaKey_throwsInvalidHolderKey() {
        JsonNode node = json("{\"jwk\":{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }

    @Test
    void fromJson_withOversizedJwkNode_throwsInvalidHolderKey() {
        String oversizedCoordinate = "A".repeat(10_000);
        JsonNode node = json("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + oversizedCoordinate + "\",\"y\":\"def\"}}");
        assertThrows(InvalidHolderKeyException.class, () -> HolderKey.fromJson(node));
    }
}
