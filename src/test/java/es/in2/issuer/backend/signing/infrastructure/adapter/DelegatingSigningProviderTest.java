package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.*;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DelegatingSigningProviderTest {

    @Mock TenantSigningConfigService tenantSigningConfigService;
    @Mock SigningProvider signHashProvider;
    @Mock SigningProvider signDocProvider;

    private static SigningRequest jadesRequest() {
        var ctx = new SigningContext("token", "issuanceId", "email@example.com");
        return SigningRequest.builder()
                .type(SigningType.JADES)
                .data("{\"vc\":\"unsigned\"}")
                .context(ctx)
                .build();
    }

    private static RemoteSignatureDto cfgWithOperation(String operation) {
        return new RemoteSignatureDto(
                "https://mock-qtsp.example.com",
                "client", "secret", "cred-001", "password", "PT10M",
                operation
        );
    }

    private DelegatingSigningProvider newSut() {
        return new DelegatingSigningProvider(
                Map.of("sign-hash", signHashProvider, "sign-doc", signDocProvider),
                tenantSigningConfigService
        );
    }

    @Test
    void sign_delegatesToSignHash_andInjectsCfgIntoRequest() {
        when(tenantSigningConfigService.getRemoteSignature())
                .thenReturn(Mono.just(cfgWithOperation("sign-hash")));

        SigningResult expected = new SigningResult(SigningType.JADES, "jwt");
        when(signHashProvider.sign(any())).thenReturn(Mono.just(expected));

        StepVerifier.create(newSut().sign(jadesRequest()))
                .assertNext(actual -> {
                    assertEquals(expected.type(), actual.type());
                    assertEquals(expected.data(), actual.data());
                })
                .verifyComplete();

        ArgumentCaptor<SigningRequest> captor = ArgumentCaptor.forClass(SigningRequest.class);
        verify(signHashProvider).sign(captor.capture());
        assertNotNull(captor.getValue().remoteSignature(), "cfg must be injected into the request");
        verify(signDocProvider, never()).sign(any());
    }

    @Test
    void sign_delegatesToSignDoc_whenOperationIsSignDoc() {
        when(tenantSigningConfigService.getRemoteSignature())
                .thenReturn(Mono.just(cfgWithOperation("sign-doc")));

        SigningResult expected = new SigningResult(SigningType.JADES, "signed-via-doc");
        when(signDocProvider.sign(any())).thenReturn(Mono.just(expected));

        StepVerifier.create(newSut().sign(jadesRequest()))
                .expectNext(expected)
                .verifyComplete();

        verify(signDocProvider).sign(any());
        verify(signHashProvider, never()).sign(any());
    }

    @Test
    void sign_returnsError_whenTenantHasNoRemoteSignatureConfigured() {
        when(tenantSigningConfigService.getRemoteSignature()).thenReturn(Mono.empty());

        StepVerifier.create(newSut().sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("No remote signature configuration"));
                })
                .verify();

        verifyNoInteractions(signHashProvider, signDocProvider);
    }

    @Test
    void sign_returnsError_whenSigningOperationIsNull() {
        when(tenantSigningConfigService.getRemoteSignature())
                .thenReturn(Mono.just(cfgWithOperation(null)));

        StepVerifier.create(newSut().sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("signingOperation is required"));
                })
                .verify();

        verifyNoInteractions(signHashProvider);
    }

    @Test
    void sign_returnsError_whenOperationNotRegistered() {
        when(tenantSigningConfigService.getRemoteSignature())
                .thenReturn(Mono.just(cfgWithOperation("unknown-op")));

        StepVerifier.create(newSut().sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("No SigningProvider for operation 'unknown-op'"));
                })
                .verify();

        verifyNoInteractions(signHashProvider);
    }

    @Test
    void sign_propagatesDelegateError() {
        when(tenantSigningConfigService.getRemoteSignature())
                .thenReturn(Mono.just(cfgWithOperation("sign-hash")));

        when(signHashProvider.sign(any()))
                .thenReturn(Mono.error(new SigningException("delegate failed")));

        StepVerifier.create(newSut().sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertEquals("delegate failed", ex.getMessage());
                })
                .verify();

        verify(signHashProvider).sign(any());
    }
}
