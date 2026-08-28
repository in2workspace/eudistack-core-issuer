package es.in2.issuer.backend.shared.domain.util;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class UtilsTest {

    @Test
    void testGenerateCustomNonce() {
        StepVerifier.create(Utils.generateCustomNonce())
                .assertNext(nonce -> {
                    assertNotNull(nonce);
                    assertFalse(nonce.isEmpty());
                    assertDoesNotThrow(() -> Base64.getUrlDecoder().decode(nonce));
                })
                .verifyComplete();
    }

    @Test
    void testGenerateSecureAuthorizationCode() {
        StepVerifier.create(Utils.generateSecureAuthorizationCode())
                .assertNext(code -> {
                    assertNotNull(code);
                    byte[] decoded = Base64.getUrlDecoder().decode(code);
                    assertEquals(32, decoded.length);
                })
                .verifyComplete();
    }

    @Test
    void testGenerateSecureAuthorizationCode_producesDistinctValues() {
        StepVerifier.create(Utils.generateSecureAuthorizationCode())
                .assertNext(first ->
                        StepVerifier.create(Utils.generateSecureAuthorizationCode())
                                .assertNext(second -> assertNotEquals(first, second))
                                .verifyComplete())
                .verifyComplete();
    }

}