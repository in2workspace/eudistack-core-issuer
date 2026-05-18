package es.in2.issuer.backend.signing.infrastructure.adapter.impl;

import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningProviderResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DelegatingSigningProviderImplTest {

    @Mock
    private TenantSigningConfigService tenantSigningConfigService;

    @Mock
    private SigningProviderResolver signingProviderResolver;

    @Mock
    private SigningProvider signHashProvider;

    @Mock
    private SigningProvider signDocProvider;

    @InjectMocks
    private DelegatingSigningProviderImpl delegatingSigningProvider;

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
                "provider",
                "1",
                "https://qtsp.test",
                operation,
                "cred-123", "pwd",
                "PT10M",
                "clientId", "clientSecret",
                "",
                "",
                "",
                "",
                ""
        );
    }

    @Test
    void sign_delegatesToSignHash_andInjectsCfgIntoRequest() {
        String operation = "sign-hash";
        when(signingProviderResolver.resolveFromValue(operation))
                .thenReturn(signHashProvider);

        when(tenantSigningConfigService.getRemoteSignature())
                .thenReturn(Mono.just(cfgWithOperation(operation)));

        SigningResult expected = new SigningResult(SigningType.JADES, "jwt");
        when(signHashProvider.sign(any())).thenReturn(Mono.just(expected));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
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
        String operation = "sign-doc";
        when(signingProviderResolver.resolveFromValue(operation))
                .thenReturn(signDocProvider);
        when(tenantSigningConfigService.getRemoteSignature())
                .thenReturn(Mono.just(cfgWithOperation(operation)));

        SigningResult expected = new SigningResult(SigningType.JADES, "signed-via-doc");
        when(signDocProvider.sign(any())).thenReturn(Mono.just(expected));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectNext(expected)
                .verifyComplete();

        verify(signDocProvider).sign(any());
        verify(signHashProvider, never()).sign(any());
    }

    @Test
    void sign_returnsError_whenTenantHasNoRemoteSignatureConfigured() {
        when(tenantSigningConfigService.getRemoteSignature()).thenReturn(Mono.empty());

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
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

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("signingOperation is required"));
                })
                .verify();

        verifyNoInteractions(signHashProvider);
    }

    @Test
    void sign_returnsError_whenOperationNotRegistered() {
        String operation = "unknown-op";
        when(signingProviderResolver.resolveFromValue(operation))
                .thenThrow(new SigningException("No SigningProvider for operation '" + operation + "'"));
        when(tenantSigningConfigService.getRemoteSignature())
                .thenReturn(Mono.just(cfgWithOperation(operation)));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("No SigningProvider for operation 'unknown-op'"));
                })
                .verify();

        verifyNoInteractions(signHashProvider);
    }

    @Test
    void sign_propagatesDelegateError() {
        String operation = "sign-hash";
        when(signingProviderResolver.resolveFromValue(operation))
                .thenReturn(signHashProvider);

        when(tenantSigningConfigService.getRemoteSignature())
                .thenReturn(Mono.just(cfgWithOperation(operation)));

        when(signHashProvider.sign(any()))
                .thenReturn(Mono.error(new SigningException("delegate failed")));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertEquals("delegate failed", ex.getMessage());
                })
                .verify();

        verify(signHashProvider).sign(any());
    }
}
