package es.in2.issuer.backend.signing.infrastructure.controller;

import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SigningRuntimeConfigControllerTest {

    @Mock
    private RuntimeSigningConfig runtimeSigningConfig;

    @InjectMocks
    private SigningRuntimeConfigController controller;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getProviderReturnsProviderFromConfig() {
        when(runtimeSigningConfig.getProvider()).thenReturn("test-provider");
        ResponseEntity<Map<String, String>> response = controller.getProvider();
        assertEquals(200, response.getStatusCodeValue());
        assertEquals("test-provider", response.getBody().get("provider"));
    }

    @Test
    void setProviderUpdatesProviderAndReturnsIt() {
        when(runtimeSigningConfig.getProvider()).thenReturn("new-provider");
        Map<String, String> body = Map.of("provider", "new-provider");
        ResponseEntity<Map<String, String>> response = controller.setProvider(body);
        verify(runtimeSigningConfig).setProvider("new-provider");
        assertEquals(200, response.getStatusCodeValue());
        assertEquals("new-provider", response.getBody().get("provider"));
    }

    @Test
    void setProviderReturnsBadRequestIfProviderMissing() {
        Map<String, String> body = Map.of();
        ResponseEntity<Map<String, String>> response = controller.setProvider(body);
        assertEquals(400, response.getStatusCodeValue());
        assertEquals("Missing field 'provider'", response.getBody().get("error"));
    }

    @Test
    void setProviderReturnsBadRequestIfProviderBlank() {
        Map<String, String> body = Map.of("provider", "   ");
        ResponseEntity<Map<String, String>> response = controller.setProvider(body);
        assertEquals(400, response.getStatusCodeValue());
        assertEquals("Missing field 'provider'", response.getBody().get("error"));
    }
}