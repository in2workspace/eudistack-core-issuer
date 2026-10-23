package es.in2.issuer.backend.signing.infrastructure.adapter.impl;

import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningProviderType;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningAuditor;
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
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
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

    @Mock
    private SigningProvider kmsProvider;

    @Mock
    private SigningAuditor signingAuditor;

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

    private static ActiveSigningConfig qtsp(String operation) {
        return ActiveSigningConfig.qtsp(cfgWithOperation(operation));
    }

    private static RemoteSignatureDto cfgWithOperation(String operation) {
        return new RemoteSignatureDto(
                "provider",
                "1",
                "https://qtsp.test",
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

        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(qtsp(operation)));

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
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(qtsp(operation)));

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
        when(tenantSigningConfigService.getActiveSigningConfig()).thenReturn(Mono.empty());

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertTrue(ex.getMessage().contains("No remote signature configuration"));
                    assertEquals(SigningFailureReason.NO_CONFIGURATION, ((SigningException) ex).getReason());
                })
                .verify();

        verifyNoInteractions(signHashProvider, signDocProvider);
    }

    @Test
    void sign_returnsError_whenSigningOperationIsNull() {
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(qtsp(null)));

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
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(qtsp(operation)));

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

        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(qtsp(operation)));

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

    private void givenSignHashFailsWith(Throwable error) {
        when(signingProviderResolver.resolveFromValue("sign-hash")).thenReturn(signHashProvider);
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(qtsp("sign-hash")));
        when(signHashProvider.sign(any())).thenReturn(Mono.error(error));
    }

    @Test
    void sign_recoverableFailure_isClassifiedAsServiceUnavailable() {
        var recoverable = new SigningException("Signing failed", new java.net.ConnectException("refused"));
        givenSignHashFailsWith(recoverable);

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertEquals(SigningFailureReason.PROVIDER_UNAVAILABLE, ((SigningException) ex).getReason());
                    assertSame(recoverable, ex.getCause());
                    assertEquals("Signing failed", ex.getMessage());
                })
                .verify();
    }

    @Test
    void sign_recoverableNonSigningFailure_isWrappedAsServiceUnavailable() {
        givenSignHashFailsWith(new java.util.concurrent.TimeoutException("slow"));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertEquals(SigningFailureReason.PROVIDER_UNAVAILABLE, ((SigningException) ex).getReason());
                })
                .verify();
    }

    @Test
    void sign_failureWithKmsReason_isKeptUnchanged() {
        var kms = new KmsSigningException(SigningFailureReason.KEY_UNUSABLE, "disabled",
                new java.net.ConnectException("irrelevant"));
        givenSignHashFailsWith(kms);

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> assertSame(kms, ex))
                .verify();
    }

    @Test
    void sign_unknownFailure_staysUnchangedAndReadsAsOther() {
        var unknown = new IllegalStateException("boom");
        givenSignHashFailsWith(unknown);

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertSame(unknown, ex);
                    assertEquals(SigningFailureReason.OTHER,
                            es.in2.issuer.backend.signing.domain.util.SigningFailureReasons.of(ex));
                })
                .verify();
    }

    private static OwnKeySigningConfig ownKey(String keyRef) {
        return new OwnKeySigningConfig(keyRef, "ES256", java.util.List.of("MIIB-leaf"));
    }

    @Test
    void sign_ownKeyModality_delegatesToKmsProvider_andNeverTouchesQtspProviders() {
        var ownKey = ownKey("arn:aws:kms:eu-west-1:111122223333:key/k");
        var expected = new SigningResult(SigningType.JADES, "own-key-jws");
        var request = jadesRequest();
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(ActiveSigningConfig.ownKey(ownKey)));
        when(signingProviderResolver.resolve(SigningProviderType.AWS_KMS)).thenReturn(kmsProvider);
        when(kmsProvider.sign(any())).thenReturn(Mono.just(expected));

        StepVerifier.create(delegatingSigningProvider.sign(request))
                .expectNext(expected)
                .verifyComplete();

        var captor = ArgumentCaptor.forClass(SigningRequest.class);
        verify(kmsProvider).sign(captor.capture());
        assertEquals(ownKey, captor.getValue().ownKey());
        assertNull(captor.getValue().remoteSignature());
        assertEquals(request.data(), captor.getValue().data());
        verify(signingProviderResolver, never()).resolveFromValue(any());
        verifyNoInteractions(signHashProvider, signDocProvider);
    }

    @Test
    void sign_ownKeyModality_kmsReasonReachesTheCallerUnchanged() {
        var ownKey = ownKey("arn:aws:kms:eu-west-1:111122223333:key/k");
        var kms = new KmsSigningException(SigningFailureReason.PROVIDER_UNAVAILABLE, "kms down");
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(ActiveSigningConfig.ownKey(ownKey)));
        when(signingProviderResolver.resolve(SigningProviderType.AWS_KMS)).thenReturn(kmsProvider);
        when(kmsProvider.sign(any())).thenReturn(Mono.error(kms));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> assertSame(kms, ex))
                .verify();
    }

    @Test
    void sign_twoTenants_eachResolvesItsOwnConfigurationAndKeyRef() {
        var tenantA = ownKey("arn:aws:kms:eu-west-1:111122223333:key/tenant-a");
        var tenantB = ownKey("arn:aws:kms:eu-west-1:111122223333:key/tenant-b");
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.deferContextual(ctx -> Mono.just(ActiveSigningConfig.ownKey(
                        "a".equals(ctx.get(TENANT_DOMAIN_CONTEXT_KEY)) ? tenantA : tenantB))));
        when(signingProviderResolver.resolve(SigningProviderType.AWS_KMS)).thenReturn(kmsProvider);
        when(kmsProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "jws")));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "a"))).expectNextCount(1).verifyComplete();
        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "b"))).expectNextCount(1).verifyComplete();

        var captor = ArgumentCaptor.forClass(SigningRequest.class);
        verify(kmsProvider, times(2)).sign(captor.capture());
        assertEquals(java.util.List.of(tenantA, tenantB),
                captor.getAllValues().stream().map(SigningRequest::ownKey).toList());
    }

    @Test
    void sign_requestWithRemoteSignature_skipsConfigLookup() {
        when(signingProviderResolver.resolveFromValue("sign-hash")).thenReturn(signHashProvider);
        when(signHashProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "jwt")));
        var request = SigningRequest.builder()
                .type(SigningType.JADES)
                .data("{}")
                .context(new SigningContext("token", "issuanceId", "email@example.com"))
                .remoteSignature(cfgWithOperation("sign-hash"))
                .build();

        StepVerifier.create(delegatingSigningProvider.sign(request)).expectNextCount(1).verifyComplete();

        verifyNoInteractions(tenantSigningConfigService);
    }
}
