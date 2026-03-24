package es.in2.issuer.backend.issuance.infrastructure.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryBootstrapTokenServiceTest {

    @Test
    void shouldGenerateTokenOnConstruction() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService("");
        String token = service.getToken();
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    @Test
    void shouldAcceptValidToken() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService("");
        String token = service.getToken();

        assertTrue(service.consumeIfValid(token));
        assertNotNull(service.getToken(), "Token should remain valid after use");
    }

    @Test
    void shouldAcceptRepeatedUse() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService("");
        String token = service.getToken();

        assertTrue(service.consumeIfValid(token));
        assertTrue(service.consumeIfValid(token), "Token should be reusable");
    }

    @Test
    void shouldAcceptTokenWithDifferentStringReference() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService("");
        String token = service.getToken();
        // Simulate a token arriving from HTTP header (different String object)
        String copy = new String(token);
        assertNotSame(token, copy);

        assertTrue(service.consumeIfValid(copy));
        assertNotNull(service.getToken(), "Token should remain valid after use");
    }

    @Test
    void shouldRejectInvalidToken() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService("");

        assertFalse(service.consumeIfValid("wrong-token"));
        assertNotNull(service.getToken());
    }

    @Test
    void shouldRejectNullToken() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService("");

        assertFalse(service.consumeIfValid(null));
        assertNotNull(service.getToken());
    }

    @Test
    void shouldRejectBlankToken() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService("");

        assertFalse(service.consumeIfValid(""));
        assertFalse(service.consumeIfValid("   "));
        assertNotNull(service.getToken());
    }
}
