package es.in2.issuer.backend.shared.domain.service;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PkceVerifierTest {

    private final PkceVerifier pkceVerifier = new PkceVerifier();

    @Test
    void verifyS256_shouldSucceedWithValidVerifierAndChallenge() throws Exception {
        String codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String codeChallenge = computeS256(codeVerifier);

        assertDoesNotThrow(() -> pkceVerifier.verifyS256(codeVerifier, codeChallenge));
    }

    @Test
    void verifyS256_shouldFailWithWrongVerifier() throws Exception {
        String codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String codeChallenge = computeS256(codeVerifier);

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> pkceVerifier.verifyS256("wrong-verifier-that-is-long-enough-to-pass-43-chars", codeChallenge)
        );
        assertEquals("PKCE verification failed", ex.getMessage());
    }

    @Test
    void verifyS256_shouldThrowOnNullVerifier() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> pkceVerifier.verifyS256(null, "some-challenge")
        );
        assertEquals("Missing code_verifier", ex.getMessage());
    }

    @Test
    void verifyS256_shouldThrowOnBlankVerifier() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> pkceVerifier.verifyS256("  ", "some-challenge")
        );
        assertEquals("Missing code_verifier", ex.getMessage());
    }

    @Test
    void verifyS256_shouldThrowOnNullChallenge() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> pkceVerifier.verifyS256("some-verifier-that-is-long-enough-to-pass-43-chars-check", null)
        );
        assertEquals("Missing code_challenge", ex.getMessage());
    }

    @Test
    void verifyS256_shouldThrowOnBlankChallenge() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> pkceVerifier.verifyS256("some-verifier-that-is-long-enough-to-pass-43-chars-check", "  ")
        );
        assertEquals("Missing code_challenge", ex.getMessage());
    }

    @Test
    void verifyS256_shouldWorkWithRfc7636AppendixBTestVector() throws Exception {
        // RFC 7636 Appendix B test vector
        String codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        // Expected S256 challenge for this verifier
        String expectedChallenge = computeS256(codeVerifier);

        assertDoesNotThrow(() -> pkceVerifier.verifyS256(codeVerifier, expectedChallenge));
    }

    private String computeS256(String codeVerifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
