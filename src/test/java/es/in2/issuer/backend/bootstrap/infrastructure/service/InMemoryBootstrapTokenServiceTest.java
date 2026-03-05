package es.in2.issuer.backend.bootstrap.infrastructure.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryBootstrapTokenServiceTest {

    @Test
    void shouldGenerateTokenOnConstruction() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService();
        String token = service.getToken();
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    @Test
    void shouldConsumeValidToken() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService();
        String token = service.getToken();

        assertTrue(service.consumeIfValid(token));
        assertNull(service.getToken());
    }

    @Test
    void shouldRejectSecondConsumption() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService();
        String token = service.getToken();

        assertTrue(service.consumeIfValid(token));
        assertFalse(service.consumeIfValid(token));
    }

    @Test
    void shouldConsumeTokenWithDifferentStringReference() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService();
        String token = service.getToken();
        // Simulate a token arriving from HTTP header (different String object)
        String copy = new String(token);
        assertNotSame(token, copy);

        assertTrue(service.consumeIfValid(copy));
        assertNull(service.getToken());
    }

    @Test
    void shouldRejectInvalidToken() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService();

        assertFalse(service.consumeIfValid("wrong-token"));
        assertNotNull(service.getToken());
    }

    @Test
    void shouldRejectNullToken() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService();

        assertFalse(service.consumeIfValid(null));
        assertNotNull(service.getToken());
    }

    @Test
    void shouldRejectBlankToken() {
        InMemoryBootstrapTokenService service = new InMemoryBootstrapTokenService();

        assertFalse(service.consumeIfValid(""));
        assertFalse(service.consumeIfValid("   "));
        assertNotNull(service.getToken());
    }
}
