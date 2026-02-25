package es.in2.issuer.backend.signing.infrastructure.qtsp.signhash;

import org.mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import es.in2.issuer.backend.signing.infrastructure.config.RemoteSignatureConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class QtspSignHashClientTest {

    @Mock
    private RemoteSignatureConfig remoteSignatureConfig;

    @Mock
    private HttpUtils httpUtils;

    private ObjectMapper objectMapper;
    private QtspSignHashClient client;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        client = new QtspSignHashClient(objectMapper, remoteSignatureConfig, httpUtils);
    }

    @Test
    void authorizeForHash_success_returnsSad() {
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://qtsp.test");
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("cred-123");
        when(remoteSignatureConfig.getRemoteSignatureCredentialPassword()).thenReturn("pwd");

        when(httpUtils.postRequest(
                eq("https://qtsp.test/csc/v2/credentials/authorize"),
                anyList(),
                anyString()
        )).thenReturn(Mono.just("{\"SAD\":\"sad-token-123\"}"));

        StepVerifier.create(client.authorizeForHash("access-token", "hashB64Url", "2.16.840.1.101.3.4.2.1"))
                .expectNext("sad-token-123")
                .verifyComplete();
    }

    @Test
    void authorizeForHash_emptySad_shouldError() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{}"));

        StepVerifier.create(client.authorizeForHash("access-token", "hashB64Url", "2.16.840.1.101.3.4.2.1"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Empty authorize response"));
                })
                .verify();
    }

    @Test
    void authorizeForHash_unauthorized_mapsToRemoteSignatureException() {
        WebClientResponseException unauthorized = WebClientResponseException.create(
                HttpStatus.UNAUTHORIZED.value(),
                "Unauthorized",
                null,
                new byte[0],
                StandardCharsets.UTF_8
        );

        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.error(unauthorized));

        StepVerifier.create(client.authorizeForHash("access-token", "hashB64Url", "2.16.840.1.101.3.4.2.1"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Unauthorized on authorize(signHash)"));
                })
                .verify();
    }

    @Test
    void signHash_success_returnsFirstSignature() {
        // config necesaria para construir endpoint y body
        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://qtsp.test");
        when(remoteSignatureConfig.getRemoteSignatureCredentialId()).thenReturn("cred-123");

        when(httpUtils.postRequest(
                eq("https://qtsp.test/csc/v2/signatures/signHash"),
                anyList(),
                anyString()
        )).thenReturn(Mono.just("{\"signatures\":[\"sig-abc\"]}"));

        StepVerifier.create(client.signHash(
                        "access-token",
                        "sad-1",
                        "hashB64Url",
                        "2.16.840.1.101.3.4.2.1",
                        "1.2.840.10045.4.3.2"
                ))
                .expectNext("sig-abc")
                .verifyComplete();
    }

    @Test
    void signHash_missingSignatures_shouldError() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{\"signatures\":[]}"));

        StepVerifier.create(client.signHash("access-token", "sad-1", "hashB64Url",
                        "2.16.840.1.101.3.4.2.1",
                        "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("signHash response missing signatures[0]"));
                })
                .verify();
    }

    @Test
    void signHash_unauthorized_mapsToRemoteSignatureException() {
        WebClientResponseException unauthorized = WebClientResponseException.create(
                HttpStatus.UNAUTHORIZED.value(),
                "Unauthorized",
                null,
                new byte[0],
                StandardCharsets.UTF_8
        );

        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.error(unauthorized));

        StepVerifier.create(client.signHash("access-token", "sad-1", "hashB64Url",
                        "2.16.840.1.101.3.4.2.1",
                        "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Unauthorized on signHash"));
                })
                .verify();
    }
}