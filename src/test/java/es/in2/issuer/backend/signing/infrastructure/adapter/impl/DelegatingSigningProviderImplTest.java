package es.in2.issuer.backend.signing.infrastructure.adapter.impl;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;

import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
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
    private SigningProvider qtspProvider;

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
    void sign_qtspModality_delegatesToTheQtspProvider_andInjectsCfgIntoRequest() {
        String operation = "sign-hash";
        when(signingProviderResolver.resolve(SigningModality.QTSP))
                .thenReturn(qtspProvider);

        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(qtsp(operation)));

        SigningResult expected = new SigningResult(SigningType.JADES, "jwt");
        when(qtspProvider.sign(any())).thenReturn(Mono.just(expected));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .assertNext(actual -> {
                    assertEquals(expected.type(), actual.type());
                    assertEquals(expected.data(), actual.data());
                })
                .verifyComplete();

        ArgumentCaptor<SigningRequest> captor = ArgumentCaptor.forClass(SigningRequest.class);
        verify(qtspProvider).sign(captor.capture());
        assertNotNull(captor.getValue().remoteSignature(), "cfg must be injected into the request");
        assertNull(captor.getValue().ownKey());
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

        verifyNoInteractions(qtspProvider);
    }

    @Test
    void sign_propagatesDelegateError() {
        String operation = "sign-hash";
        when(signingProviderResolver.resolve(SigningModality.QTSP))
                .thenReturn(qtspProvider);

        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(qtsp(operation)));

        when(qtspProvider.sign(any()))
                .thenReturn(Mono.error(new SigningException("delegate failed")));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> {
                    assertInstanceOf(SigningException.class, ex);
                    assertEquals("delegate failed", ex.getMessage());
                })
                .verify();

        verify(qtspProvider).sign(any());
    }

    private void givenSignHashFailsWith(Throwable error) {
        when(signingProviderResolver.resolve(SigningModality.QTSP)).thenReturn(qtspProvider);
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(qtsp("sign-hash")));
        when(qtspProvider.sign(any())).thenReturn(Mono.error(error));
    }

    /** The QTSP error reaches the caller as it is, so its HTTP response (502) is the one it had before. */
    @Test
    void sign_transientQtspFailure_reachesTheCallerUnchanged() {
        var unreachable = new RemoteSignatureException("Signature service unreachable",
                new java.net.ConnectException("refused"));
        givenSignHashFailsWith(unreachable);

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> assertSame(unreachable, ex))
                .verify();
    }

    @Test
    void sign_transientNonSigningFailure_reachesTheCallerUnchanged() {
        var slow = new java.util.concurrent.TimeoutException("slow");
        givenSignHashFailsWith(slow);

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> assertSame(slow, ex))
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
        when(signingProviderResolver.resolve(SigningModality.OWN_KEY)).thenReturn(kmsProvider);
        when(kmsProvider.sign(any())).thenReturn(Mono.just(expected));

        StepVerifier.create(delegatingSigningProvider.sign(request))
                .expectNext(expected)
                .verifyComplete();

        var captor = ArgumentCaptor.forClass(SigningRequest.class);
        verify(kmsProvider).sign(captor.capture());
        assertEquals(ownKey, captor.getValue().ownKey());
        assertNull(captor.getValue().remoteSignature());
        assertEquals(request.data(), captor.getValue().data());
        verify(signingProviderResolver, never()).resolve(SigningModality.QTSP);
        verifyNoInteractions(qtspProvider);
    }

    @Test
    void sign_ownKeyModality_kmsReasonReachesTheCallerUnchanged() {
        var ownKey = ownKey("arn:aws:kms:eu-west-1:111122223333:key/k");
        var kms = new KmsSigningException(SigningFailureReason.PROVIDER_UNAVAILABLE, "kms down");
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(ActiveSigningConfig.ownKey(ownKey)));
        when(signingProviderResolver.resolve(SigningModality.OWN_KEY)).thenReturn(kmsProvider);
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
        when(signingProviderResolver.resolve(SigningModality.OWN_KEY)).thenReturn(kmsProvider);
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
        when(signingProviderResolver.resolve(SigningModality.QTSP)).thenReturn(qtspProvider);
        when(qtspProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "jwt")));
        var request = SigningRequest.builder()
                .type(SigningType.JADES)
                .data("{}")
                .context(new SigningContext("token", "issuanceId", "email@example.com"))
                .remoteSignature(cfgWithOperation("sign-hash"))
                .build();

        StepVerifier.create(delegatingSigningProvider.sign(request)).expectNextCount(1).verifyComplete();

        verifyNoInteractions(tenantSigningConfigService);
    }

    @Test
    void sign_ownKeyDisabled_reloadsTheConfigurationAndSignsWithTheReplacement() {
        var oldKey = ownKey("arn:aws:kms:eu-west-1:111122223333:key/old");
        var newKey = ownKey("arn:aws:kms:eu-west-1:111122223333:key/new");
        var expected = new SigningResult(SigningType.JADES, "jws-new-key");
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(ActiveSigningConfig.ownKey(oldKey)));
        when(tenantSigningConfigService.reloadActiveSigningConfig())
                .thenReturn(Mono.just(ActiveSigningConfig.ownKey(newKey)));
        when(signingProviderResolver.resolve(SigningModality.OWN_KEY)).thenReturn(kmsProvider);
        when(kmsProvider.sign(any()))
                .thenReturn(Mono.error(new KmsSigningException(SigningFailureReason.KEY_UNUSABLE, "disabled")))
                .thenReturn(Mono.just(expected));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectNext(expected)
                .verifyComplete();

        var captor = ArgumentCaptor.forClass(SigningRequest.class);
        verify(kmsProvider, times(2)).sign(captor.capture());
        assertEquals(java.util.List.of(oldKey, newKey),
                captor.getAllValues().stream().map(SigningRequest::ownKey).toList());
        verify(tenantSigningConfigService).reloadActiveSigningConfig();
    }

    @Test
    void sign_ownKeyDisabledAndWithdrawn_failsWithNoConfiguration() {
        var oldKey = ownKey("arn:aws:kms:eu-west-1:111122223333:key/old");
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(ActiveSigningConfig.ownKey(oldKey)));
        when(tenantSigningConfigService.reloadActiveSigningConfig()).thenReturn(Mono.empty());
        when(signingProviderResolver.resolve(SigningModality.OWN_KEY)).thenReturn(kmsProvider);
        when(kmsProvider.sign(any()))
                .thenReturn(Mono.error(new KmsSigningException(SigningFailureReason.KEY_UNUSABLE, "disabled")));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> assertEquals(SigningFailureReason.NO_CONFIGURATION,
                        es.in2.issuer.backend.signing.domain.util.SigningFailureReasons.of(ex)))
                .verify();
        verify(kmsProvider, times(1)).sign(any());
    }

    @Test
    void sign_ownKeyStillDisabledAfterReload_failsWithoutASecondReload() {
        var key = ownKey("arn:aws:kms:eu-west-1:111122223333:key/k");
        var disabled = new KmsSigningException(SigningFailureReason.KEY_UNUSABLE, "disabled");
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(ActiveSigningConfig.ownKey(key)));
        when(tenantSigningConfigService.reloadActiveSigningConfig())
                .thenReturn(Mono.just(ActiveSigningConfig.ownKey(key)));
        when(signingProviderResolver.resolve(SigningModality.OWN_KEY)).thenReturn(kmsProvider);
        when(kmsProvider.sign(any())).thenReturn(Mono.error(disabled));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectErrorSatisfies(ex -> assertSame(disabled, ex))
                .verify();
        verify(kmsProvider, times(2)).sign(any());
        verify(tenantSigningConfigService, times(1)).reloadActiveSigningConfig();
    }

    @Test
    void sign_ownKeyOtherFailure_isNotReloaded() {
        var key = ownKey("arn:aws:kms:eu-west-1:111122223333:key/k");
        when(tenantSigningConfigService.getActiveSigningConfig())
                .thenReturn(Mono.just(ActiveSigningConfig.ownKey(key)));
        when(signingProviderResolver.resolve(SigningModality.OWN_KEY)).thenReturn(kmsProvider);
        when(kmsProvider.sign(any()))
                .thenReturn(Mono.error(new KmsSigningException(SigningFailureReason.INVALID_RESPONSE, "bad")));

        StepVerifier.create(delegatingSigningProvider.sign(jadesRequest()))
                .expectError(KmsSigningException.class)
                .verify();
        verify(tenantSigningConfigService, never()).reloadActiveSigningConfig();
    }
}
