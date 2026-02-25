package es.in2.issuer.backend.signing.infrastructure.controller;

import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningConfigPushRequest;
import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SigningRuntimeConfigControllerTest {

    @Mock
    private RuntimeSigningConfig runtimeSigningConfig;

    @InjectMocks
    private SigningRuntimeConfigController controller;

    @Test
    void getProviderReturnsProviderFromConfig() {
        when(runtimeSigningConfig.getProvider()).thenReturn("test-provider");

        ResponseEntity<Map<String, String>> response = controller.getProvider();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("test-provider", response.getBody().get("provider"));
    }

    @Test
    void pushSigningConfig_updatesProviderAndRemoteSignature_andReturnsOk() {

        // Given
        RemoteSignatureDto remote = new RemoteSignatureDto(
                "cloud",
                "https://api.external.com",
                "/sign",
                "clientId",
                "clientSecret",
                "cred-id",
                "pwd",
                "PT10M"
        );

        SigningConfigPushRequest request = new SigningConfigPushRequest("csc-sign-hash", remote);

        when(runtimeSigningConfig.getProvider()).thenReturn("csc-sign-hash");

        // When
        ResponseEntity<Map<String, String>> response = controller.pushSigningConfig(request);

        // Then
        verify(runtimeSigningConfig).setProvider("csc-sign-hash");
        verify(runtimeSigningConfig).setRemoteSignature(remote);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("csc-sign-hash", response.getBody().get("provider"));
        assertEquals("updated", response.getBody().get("status"));
    }

    @Test
    void pushSigningConfig_returnsBadRequest_whenProviderBlank() {

        RemoteSignatureDto remote = new RemoteSignatureDto(
                "cloud",
                "https://api.external.com",
                "/sign",
                "clientId",
                "clientSecret",
                "cred-id",
                "pwd",
                "PT10M"
        );

        SigningConfigPushRequest request = new SigningConfigPushRequest("   ", remote);
        ResponseEntity<Map<String, String>> response = controller.pushSigningConfig(request);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().get("error").contains("provider"));
    }
}