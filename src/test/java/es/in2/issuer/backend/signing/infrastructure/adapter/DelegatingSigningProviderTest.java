package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.*;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DelegatingSigningProviderTest {

    @Mock RuntimeSigningConfig runtimeSigningConfig;
    @Mock SigningProvider signHashProvider;
    @Mock SigningProvider signDocProvider;

    private static SigningRequest jadesRequest() {
        var ctx = new SigningContext("token", "issuanceId", "email@example.com");
        return new SigningRequest(SigningType.JADES, "{\"vc\":\"unsigned\"}", ctx, null);
    }

    private static RemoteSignatureDto cfgWithOperation(String operation) {
        return new RemoteSignatureDto(
                "https://mock-qtsp.example.com",
                "client", "secret", "cred-001", "password", "PT10M",
                operation
        );
    }

    @Test
    void sign_delegatesToSignHash_whenOperationIsSignHash() {
        when(runtimeSigningConfig.getProvider()).thenReturn("altia-mock-qtsp");
        when(runtimeSigningConfig.getRemoteSignature()).thenReturn(cfgWithOperation("sign-hash"));

        SigningResult expected = new SigningResult(SigningType.JADES, "jwt");
        when(signHashProvider.sign(any())).thenReturn(Mono.just(expected));

        var sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("sign-hash", signHashProvider, "sign-doc", signDocProvider)
        );

        StepVerifier.create(sut.sign(jadesRequest()))
                .assertNext(actual -> {
                    assertEquals(expected.type(), actual.type());
                    assertEquals(expected.data(), actual.data());
                })
                .verifyComplete();

        verify(signHashProvider).sign(any());
        verify(signDocProvider, never()).sign(any());
    }

    @Test
    void sign_delegatesToSignDoc_whenOperationIsSignDoc() {
        when(runtimeSigningConfig.getProvider()).thenReturn("signDoc-only-qtsp");
        when(runtimeSigningConfig.getRemoteSignature()).thenReturn(cfgWithOperation("sign-doc"));

        SigningResult expected = new SigningResult(SigningType.JADES, "signed-via-doc");
        when(signDocProvider.sign(any())).thenReturn(Mono.just(expected));

        var sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("sign-hash", signHashProvider, "sign-doc", signDocProvider)
        );

        StepVerifier.create(sut.sign(jadesRequest()))
                .expectNext(expected)
                .verifyComplete();

        verify(signDocProvider).sign(any());
        verify(signHashProvider, never()).sign(any());
    }

    @Test
    void sign_returnsError_whenNoRemoteSignatureConfigured() {
        when(runtimeSigningConfig.getRemoteSignature()).thenReturn(null);

        var sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("sign-hash", signHashProvider)
        );

        StepVerifier.create(sut.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("No remote signature configuration"));
                })
                .verify();

        verifyNoInteractions(signHashProvider);
    }

    @Test
    void sign_returnsError_whenSigningOperationIsNull() {
        when(runtimeSigningConfig.getRemoteSignature()).thenReturn(cfgWithOperation(null));

        var sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("sign-hash", signHashProvider)
        );

        StepVerifier.create(sut.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("signingOperation is required"));
                })
                .verify();

        verifyNoInteractions(signHashProvider);
    }

    @Test
    void sign_returnsError_whenSigningOperationIsBlank() {
        when(runtimeSigningConfig.getRemoteSignature()).thenReturn(cfgWithOperation("  "));

        var sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("sign-hash", signHashProvider)
        );

        StepVerifier.create(sut.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("signingOperation is required"));
                })
                .verify();

        verifyNoInteractions(signHashProvider);
    }

    @Test
    void sign_returnsError_whenOperationNotRegistered() {
        when(runtimeSigningConfig.getRemoteSignature()).thenReturn(cfgWithOperation("unknown-op"));

        var sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("sign-hash", signHashProvider)
        );

        StepVerifier.create(sut.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("No SigningProvider for operation 'unknown-op'"));
                })
                .verify();

        verifyNoInteractions(signHashProvider);
    }

    @Test
    void sign_propagatesDelegateError() {
        when(runtimeSigningConfig.getProvider()).thenReturn("altia-mock-qtsp");
        when(runtimeSigningConfig.getRemoteSignature()).thenReturn(cfgWithOperation("sign-hash"));

        when(signHashProvider.sign(any()))
                .thenReturn(Mono.error(new SigningException("delegate failed")));

        var sut = new DelegatingSigningProvider(
                runtimeSigningConfig,
                Map.of("sign-hash", signHashProvider)
        );

        StepVerifier.create(sut.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertEquals("delegate failed", ex.getMessage());
                })
                .verify();

        verify(signHashProvider).sign(any());
    }
}
