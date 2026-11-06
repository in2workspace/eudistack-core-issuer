package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents.SignatureProof;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwsHeaderFingerprintTest {

    private static final byte[] CERTIFICATE = "certificate-der".getBytes(StandardCharsets.UTF_8);

    private static String jwsWithHeader(String headerJson) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        return header + ".payload.signature";
    }

    private static String headerWithCertificate() {
        return "{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString(CERTIFICATE) + "\"]}";
    }

    @Test
    void of_jwsWithAlgorithmAndCertificate_returnsTheAlgorithmAndTheCertificateFingerprint() throws NoSuchAlgorithmException {
        // Arrange
        String expected = "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(CERTIFICATE));

        // Act
        Optional<SignatureProof> proof = JwsHeaderFingerprint.of(jwsWithHeader(headerWithCertificate()));

        // Assert
        assertEquals("ES256", proof.orElseThrow().algorithm());
        assertEquals(expected, proof.orElseThrow().certificateHash());
    }

    @Test
    void of_sdJwtWithDisclosures_readsOnlyTheSignedPart() {
        // Arrange
        String sdJwt = jwsWithHeader(headerWithCertificate()) + "~disclosure1~disclosure2~";

        // Act
        Optional<SignatureProof> proof = JwsHeaderFingerprint.of(sdJwt);

        // Assert
        assertEquals("ES256", proof.orElseThrow().algorithm());
    }

    @Test
    void of_jwsWithoutCertificateChain_returnsEmpty() {
        // Arrange
        String jws = jwsWithHeader("{\"alg\":\"ES256\"}");

        // Act
        Optional<SignatureProof> proof = JwsHeaderFingerprint.of(jws);

        // Assert
        assertTrue(proof.isEmpty());
    }

    @Test
    void of_jwsWithoutAlgorithm_returnsEmpty() {
        // Arrange
        String jws = jwsWithHeader("{\"x5c\":[\"" + Base64.getEncoder().encodeToString(CERTIFICATE) + "\"]}");

        // Act
        Optional<SignatureProof> proof = JwsHeaderFingerprint.of(jws);

        // Assert
        assertTrue(proof.isEmpty());
    }

    @Test
    void of_valueThatIsNotAJws_returnsEmpty() {
        // Arrange & Act
        Optional<SignatureProof> notAJws = JwsHeaderFingerprint.of("not-a-jws");
        Optional<SignatureProof> garbledHeader = JwsHeaderFingerprint.of("%%%.payload.signature");
        Optional<SignatureProof> nothing = JwsHeaderFingerprint.of(null);

        // Assert
        assertTrue(notAJws.isEmpty());
        assertTrue(garbledHeader.isEmpty());
        assertTrue(nothing.isEmpty());
    }

    @Test
    void fingerprintOf_anyValue_returnsItsSha256WithTheAlgorithmPrefix() throws NoSuchAlgorithmException {
        // Arrange
        String expected = "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(CERTIFICATE));

        // Act
        String fingerprint = JwsHeaderFingerprint.fingerprintOf(CERTIFICATE);

        // Assert
        assertEquals(expected, fingerprint);
    }
}
