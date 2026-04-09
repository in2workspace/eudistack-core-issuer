package es.in2.issuer.backend.signing.domain.service.impl;

import org.mockito.*;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import es.in2.issuer.backend.signing.domain.spi.QtspSignHashPort;
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
    @Mock QtspSignHashPort qtspSignHashClient;

    @InjectMocks JwsSignHashServiceImpl sut;

    @Test
    void signJwtWithSignHash_happyPath_buildsJwsAndCallsQtspWithCorrectArgs() throws Exception {
        // given
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";
        String signAlgoOid = "1.2.840.10045.4.3.2"; // ES256

        String headerB64 = Base64UrlUtils.encodeUtf8(headerJson);
        String payloadB64 = Base64UrlUtils.encodeUtf8(payloadJson);
        String signingInput = headerB64 + "." + payloadB64;

        byte[] signingInputBytes = signingInput.getBytes(StandardCharsets.US_ASCII);

        byte[] digest = new byte[] {1, 2, 3}; // deterministic fake digest
        String expectedHashB64Url = Base64UrlUtils.encode(digest);

        when(hashGeneratorService.sha256Digest(signingInputBytes)).thenReturn(digest);

        when(qtspSignHashClient.authorizeForHash(accessToken, expectedHashB64Url, HASH_ALGO_OID_SHA256))
                .thenReturn(Mono.just("sad-1"));

        when(qtspSignHashClient.signHash(
                accessToken,
                "sad-1",
                expectedHashB64Url,
                HASH_ALGO_OID_SHA256,
                signAlgoOid
        )).thenReturn(Mono.just("sigB64Url"));

        // when + then
        StepVerifier.create(sut.signJwtWithSignHash(accessToken, headerJson, payloadJson, signAlgoOid))
                .assertNext(jws -> assertEquals(signingInput + ".sigB64Url", jws))
                .verifyComplete();

        verify(qtspSignHashClient).authorizeForHash(accessToken, expectedHashB64Url, HASH_ALGO_OID_SHA256);
        verify(qtspSignHashClient).signHash(accessToken, "sad-1", expectedHashB64Url, HASH_ALGO_OID_SHA256, signAlgoOid);
        verifyNoMoreInteractions(qtspSignHashClient);
    }

    @Test
    void signJwtWithSignHash_whenDigestComputationFails_returnsRemoteSignatureException() throws Exception {
        // given
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";

        // We don't care exact bytes here
        when(hashGeneratorService.sha256Digest(any()))
                .thenThrow(new RuntimeException("digest fail"));

        // when + then
        StepVerifier.create(sut.signJwtWithSignHash(accessToken, headerJson, payloadJson, "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertTrue(ex.getMessage().contains("Failed to compute signingInput digest"));
                    assertNotNull(ex.getCause());
                    assertEquals("digest fail", ex.getCause().getMessage());
                })
                .verify();

        verifyNoInteractions(qtspSignHashClient);
    }

    @Test
    void signJwtWithSignHash_whenHeaderPayloadEncodingFails_returnsRemoteSignatureException() {
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";

        try (MockedStatic<Base64UrlUtils> mocked = Mockito.mockStatic(Base64UrlUtils.class)) {
            mocked.when(() -> Base64UrlUtils.encodeUtf8(anyString()))
                    .thenThrow(new RuntimeException("b64 fail"));

            StepVerifier.create(sut.signJwtWithSignHash(accessToken, headerJson, payloadJson, "1.2.840.10045.4.3.2"))
                    .expectErrorSatisfies(ex -> {
                        assertTrue(ex instanceof RemoteSignatureException);
                        assertTrue(ex.getMessage().contains("Failed to build JWS header/payload"));
                        assertNotNull(ex.getCause());
                        assertEquals("b64 fail", ex.getCause().getMessage());
                    })
                    .verify();

            verifyNoInteractions(hashGeneratorService);
            verifyNoInteractions(qtspSignHashClient);
        }
    }

    @Test
    void signJwtWithSignHash_whenAuthorizeFails_propagatesError() throws Exception {
        // given
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";

        // Make digest deterministic
        when(hashGeneratorService.sha256Digest(any())).thenReturn(new byte[] {9, 9, 9});

        when(qtspSignHashClient.authorizeForHash(anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new RemoteSignatureException("authorize failed")));

        // when + then
        StepVerifier.create(sut.signJwtWithSignHash(accessToken, headerJson, payloadJson, "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertEquals("authorize failed", ex.getMessage());
                })
                .verify();

        verify(qtspSignHashClient, times(1)).authorizeForHash(anyString(), anyString(), anyString());
        verify(qtspSignHashClient, never()).signHash(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void signJwtWithSignHash_whenSignHashFails_propagatesError() throws Exception {
        // given
        String accessToken = "access-token";
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"vc\":\"unsigned\"}";

        when(hashGeneratorService.sha256Digest(any())).thenReturn(new byte[] {7, 7, 7});

        when(qtspSignHashClient.authorizeForHash(anyString(), anyString(), anyString()))
                .thenReturn(Mono.just("sad-1"));

        when(qtspSignHashClient.signHash(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new RemoteSignatureException("signHash failed")));

        // when + then
        StepVerifier.create(sut.signJwtWithSignHash(accessToken, headerJson, payloadJson, "1.2.840.10045.4.3.2"))
                .expectErrorSatisfies(ex -> {
                    assertTrue(ex instanceof RemoteSignatureException);
                    assertEquals("signHash failed", ex.getMessage());
                })
                .verify();

        verify(qtspSignHashClient, times(1)).authorizeForHash(anyString(), anyString(), anyString());
        verify(qtspSignHashClient, times(1)).signHash(anyString(), anyString(), anyString(), anyString(), anyString());
    }
}