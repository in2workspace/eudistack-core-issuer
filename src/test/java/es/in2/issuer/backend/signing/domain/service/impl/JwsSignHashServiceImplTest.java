package es.in2.issuer.backend.signing.domain.service.impl;

import org.mockito.*;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import es.in2.issuer.backend.signing.domain.spi.CscPort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static es.in2.issuer.backend.signing.domain.service.impl.JwsSignHashServiceImpl.HASH_ALGO_OID_SHA256;


@ExtendWith(MockitoExtension.class)
class JwsSignHashServiceImplTest {

    @Mock HashGeneratorService hashGeneratorService;
    @Mock CscPort cscPort;

    @InjectMocks JwsSignHashServiceImpl sut;

    private static RemoteSignatureDto cfg() {
        return new RemoteSignatureDto(
                "provider",
                "1",
                "https://qtsp.test",
                "https://qtsp.test",
                "sign-hash",
                "clientId", "clientSecret",
                "PT10M",
                "cred-123", "pwd",
                "sign-hash",
                "",
                "",
                "",
                ""
        );
    }

    @Test
    void signJwtWithSignHash_happyPath_buildsJwsAndCallsQtspWithCorrectArgs() throws Exception {
        RemoteSignatureDto cfg = cfg();
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";
        String signAlgoOid = "1.2.840.10045.4.3.2";

        String headerB64 = Base64UrlUtils.encodeUtf8(headerJson);
        String payloadB64 = Base64UrlUtils.encodeUtf8(payloadJson);
        String signingInput = headerB64 + "." + payloadB64;

        byte[] signingInputBytes = signingInput.getBytes(StandardCharsets.US_ASCII);

        byte[] digest = new byte[] {1, 2, 3};
        // Shared service emits base64url; per-QTSP transcoding happens in the adapter.
        String expectedHashB64Url = Base64UrlUtils.encode(digest);

        when(hashGeneratorService.sha256Digest(signingInputBytes)).thenReturn(digest);

        when(cscPort.authorizeForHash(cfg, accessToken, expectedHashB64Url, HASH_ALGO_OID_SHA256))
                .thenReturn(Mono.just("sad-1"));

        when(cscPort.signHash(
                cfg,
                accessToken,
                "sad-1",
                expectedHashB64Url,
                HASH_ALGO_OID_SHA256,
                signAlgoOid
        )).thenReturn(Mono.just("sigB64Url"));

        StepVerifier.create(sut.signJwtWithSignHash(cfg, accessToken, headerJson, payloadJson, signAlgoOid))
                .assertNext(jws -> assertEquals(signingInput + ".sigB64Url", jws))
                .verifyComplete();

        verify(cscPort).authorizeForHash(cfg, accessToken, expectedHashB64Url, HASH_ALGO_OID_SHA256);
        verify(cscPort).signHash(cfg, accessToken, "sad-1", expectedHashB64Url, HASH_ALGO_OID_SHA256, signAlgoOid);
        verifyNoMoreInteractions(cscPort);
    }

    @Test
    void signJwtWithSignHash_whenDigestComputationFails_returnsRemoteSignatureException() {
        RemoteSignatureDto cfg = cfg();
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";

        when(hashGeneratorService.sha256Digest(any()))
                .thenThrow(new RuntimeException("digest fail"));

        StepVerifier.create(sut.signJwtWithSignHash(cfg, accessToken, headerJson, payloadJson, "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Failed to compute signingInput digest"));
                    assertNotNull(ex.getCause());
                    assertEquals("digest fail", ex.getCause().getMessage());
                })
                .verify();

        verifyNoInteractions(cscPort);
    }

    @Test
    void signJwtWithSignHash_whenHeaderPayloadEncodingFails_returnsRemoteSignatureException() {
        RemoteSignatureDto cfg = cfg();
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";

        try (MockedStatic<Base64UrlUtils> mocked = Mockito.mockStatic(Base64UrlUtils.class)) {
            mocked.when(() -> Base64UrlUtils.encodeUtf8(anyString()))
                    .thenThrow(new RuntimeException("b64 fail"));

            StepVerifier.create(sut.signJwtWithSignHash(cfg, accessToken, headerJson, payloadJson, "1.2.840.10045.4.3.2"))
                    .expectErrorSatisfies(ex -> {
                        assertTrue(ex instanceof RemoteSignatureException);
                        assertTrue(ex.getMessage().contains("Failed to build JWS header/payload"));
                        assertNotNull(ex.getCause());
                        assertEquals("b64 fail", ex.getCause().getMessage());
                    })
                    .verify();

            verifyNoInteractions(hashGeneratorService);
            verifyNoInteractions(cscPort);
        }
    }

    @Test
    void signJwtWithSignHash_whenAuthorizeFails_propagatesError() {
        RemoteSignatureDto cfg = cfg();
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";

        when(hashGeneratorService.sha256Digest(any())).thenReturn(new byte[] {9, 9, 9});

        when(cscPort.authorizeForHash(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new RemoteSignatureException("authorize failed")));

        StepVerifier.create(sut.signJwtWithSignHash(cfg, accessToken, headerJson, payloadJson, "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertEquals("authorize failed", ex.getMessage());
                })
                .verify();

        verify(cscPort, times(1)).authorizeForHash(any(), anyString(), anyString(), anyString());
        verify(cscPort, never()).signHash(any(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void signJwtWithSignHash_whenSignHashFails_propagatesError() {
        RemoteSignatureDto cfg = cfg();
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";

        when(hashGeneratorService.sha256Digest(any())).thenReturn(new byte[] {7, 7, 7});

        when(cscPort.authorizeForHash(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just("sad-1"));

        when(cscPort.signHash(any(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new RemoteSignatureException("signHash failed")));

        StepVerifier.create(sut.signJwtWithSignHash(cfg, accessToken, headerJson, payloadJson, "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertEquals("signHash failed", ex.getMessage());
                })
                .verify();

        verify(cscPort, times(1)).authorizeForHash(any(), anyString(), anyString(), anyString());
        verify(cscPort, times(1)).signHash(any(), anyString(), anyString(), anyString(), anyString(), anyString());
    }
}
