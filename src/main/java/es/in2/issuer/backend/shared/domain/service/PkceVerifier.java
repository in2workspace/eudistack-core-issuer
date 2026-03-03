package es.in2.issuer.backend.shared.domain.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Slf4j
@Service
public class PkceVerifier {

    public void verifyS256(String codeVerifier, String codeChallenge) {
        if (codeVerifier == null || codeVerifier.isBlank()) {
            throw new IllegalArgumentException("Missing code_verifier");
        }
        if (codeChallenge == null || codeChallenge.isBlank()) {
            throw new IllegalArgumentException("Missing code_challenge");
        }

        String computed = computeS256Challenge(codeVerifier);
        if (!computed.equals(codeChallenge)) {
            log.warn("PKCE verification failed: computed challenge does not match stored challenge");
            throw new IllegalArgumentException("PKCE verification failed");
        }
        log.debug("PKCE S256 verification succeeded");
    }

    private String computeS256Challenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
