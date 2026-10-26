package es.in2.issuer.backend.signing.infrastructure.adapter.impl;

import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.model.SigningProviderType;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningAuditor;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningProviderResolver;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Audit trail of signing attempts (EUD-289 AC-19, AC-11), through the real {@link SigningAuditor}. */
class DelegatingSigningProviderImplAuditTest {

    private static final String PAYLOAD = "{\"vc\":\"top-secret-payload\"}";
    private static final String KEY_REF = "arn:aws:kms:eu-west-1:111122223333:key/secret-key-ref";
    private static final List<String> FORBIDDEN = List.of("top-secret-payload", "secret-key-ref", "jws-value",
            "user-token", "email@example.com", "client-secret", "cred-password");

    private final AuditService auditService = mock(AuditService.class);
    private final TenantSigningConfigService configService = mock(TenantSigningConfigService.class);
    private final SigningProviderResolver resolver = mock(SigningProviderResolver.class);
    private final SigningProvider qtspProvider = mock(SigningProvider.class);
    private final SigningProvider kmsProvider = mock(SigningProvider.class);
    private DelegatingSigningProviderImpl delegating;

    @BeforeEach
    void setUp() {
        when(resolver.resolve(SigningProviderType.AWS_KMS)).thenReturn(kmsProvider);
        delegating = new DelegatingSigningProviderImpl(configService, resolver, new SigningAuditor(auditService));
    }

    private static SigningRequest request() {
        return SigningRequest.builder()
                .type(SigningType.JADES)
                .data(PAYLOAD)
                .typ("jwt")
                .context(new SigningContext("user-token", "issuance-1", "email@example.com"))
                .build();
    }

    private static ActiveSigningConfig qtsp() {
        return ActiveSigningConfig.qtsp(new RemoteSignatureDto("namirial", "2", "https://qtsp.test",
                "https://qtsp.test", "sign-hash", "cred-id", "cred-password", "PT10M", "id", "client-secret",
                null, null, null, null, null));
    }

    private static ActiveSigningConfig ownKey() {
        return ActiveSigningConfig.ownKey(new OwnKeySigningConfig(KEY_REF, "ES256", List.of("MIIB-leaf")));
    }

    private Mono<SigningResult> signAs(String tenant) {
        return delegating.sign(request()).contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> successDetails() {
        var details = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditSuccess(eq(SigningAuditor.SIGN_EVENT), eq(null), eq("signing"), eq(null),
                details.capture());
        return details.getValue();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> failureDetails(String expectedReason) {
        var details = ArgumentCaptor.forClass(Map.class);
        verify(auditService).auditFailure(eq(SigningAuditor.SIGN_EVENT), eq(null), eq(expectedReason),
                details.capture());
        return details.getValue();
    }

    private static void assertNoForbiddenData(Map<String, Object> details) {
        String all = details.toString();
        FORBIDDEN.forEach(forbidden -> assertThat(all).doesNotContain(forbidden));
        assertThat(details.keySet()).doesNotContain("payload", "jws", "token", "keyRef", "digest", "email");
    }

    @Test
    void sign_qtspSuccess_auditsSuccessWithModalityProviderAndDuration() {
        when(configService.getActiveSigningConfig()).thenReturn(Mono.just(qtsp()));
        when(resolver.resolveFromValue("sign-hash")).thenReturn(qtspProvider);
        when(qtspProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "jws-value")));

        StepVerifier.create(signAs("sandbox")).expectNextCount(1).verifyComplete();

        var details = successDetails();
        assertThat(details).containsEntry("tenant", "sandbox")
                .containsEntry("object", "JADES/jwt")
                .containsEntry("issuanceId", "issuance-1")
                .containsEntry("modality", "qtsp")
                .containsEntry("provider", "namirial")
                .containsEntry("outcome", "success");
        assertThat((Long) details.get("durationMs")).isNotNegative();
        assertNoForbiddenData(details);
    }

    @Test
    void sign_qtspFailure_auditsFailureWithClassifiedReason() {
        when(configService.getActiveSigningConfig()).thenReturn(Mono.just(qtsp()));
        when(resolver.resolveFromValue("sign-hash")).thenReturn(qtspProvider);
        when(qtspProvider.sign(any())).thenReturn(Mono.error(
                new SigningException(SigningFailureReason.PROVIDER_UNAVAILABLE, "qtsp down: client-secret")));

        StepVerifier.create(signAs("sandbox")).expectError(SigningException.class).verify();

        var details = failureDetails("PROVIDER_UNAVAILABLE");
        assertThat(details).containsEntry("modality", "qtsp").containsEntry("provider", "namirial")
                .containsEntry("outcome", "failure").containsKey("durationMs");
        assertNoForbiddenData(details);
    }

    @Test
    void sign_ownKeySuccess_auditsSuccessWithKmsProvider() {
        when(configService.getActiveSigningConfig()).thenReturn(Mono.just(ownKey()));
        when(kmsProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "jws-value")));

        StepVerifier.create(signAs("kpmg")).expectNextCount(1).verifyComplete();

        var details = successDetails();
        assertThat(details).containsEntry("tenant", "kpmg")
                .containsEntry("modality", "own_key")
                .containsEntry("provider", "aws-kms")
                .containsEntry("outcome", "success");
        assertNoForbiddenData(details);
        verifyNoInteractions(qtspProvider);
    }

    @Test
    void sign_ownKeyInvalidSignature_auditsInvalidResponse() {
        when(configService.getActiveSigningConfig()).thenReturn(Mono.just(ownKey()));
        when(kmsProvider.sign(any())).thenReturn(Mono.error(new KmsSigningException(
                SigningFailureReason.INVALID_RESPONSE, "does not verify, key " + KEY_REF)));

        StepVerifier.create(signAs("kpmg")).expectError(KmsSigningException.class).verify();

        var details = failureDetails("INVALID_RESPONSE");
        assertThat(details).containsEntry("modality", "own_key").containsEntry("provider", "aws-kms")
                .containsEntry("outcome", "failure");
        assertNoForbiddenData(details);
    }

    @Test
    void sign_noConfiguration_auditsFailureWithUnknownModality() {
        when(configService.getActiveSigningConfig()).thenReturn(Mono.empty());

        StepVerifier.create(signAs("sandbox")).expectError(SigningException.class).verify();

        var details = failureDetails("NO_CONFIGURATION");
        assertThat(details).containsEntry("modality", "unknown").containsEntry("provider", "unknown");
    }

    @Test
    void sign_withoutTenantInContext_auditsUnknownTenant() {
        when(configService.getActiveSigningConfig()).thenReturn(Mono.just(ownKey()));
        when(kmsProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "jws-value")));

        StepVerifier.create(delegating.sign(request())).expectNextCount(1).verifyComplete();

        assertThat(successDetails()).containsEntry("tenant", "unknown");
    }

    @Test
    void sign_requestWithoutTypOrContext_auditsTypeOnlyAndNoIssuanceId() {
        when(configService.getActiveSigningConfig()).thenReturn(Mono.just(ownKey()));
        when(kmsProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "jws-value")));
        var bare = SigningRequest.builder().type(SigningType.JADES).data(PAYLOAD).build();

        StepVerifier.create(delegating.sign(bare)).expectNextCount(1).verifyComplete();

        assertThat(successDetails()).containsEntry("object", "JADES").doesNotContainKey("issuanceId");
    }

    @Test
    void sign_auditServiceThrowing_neverBreaksSigning() {
        var expected = new SigningResult(SigningType.JADES, "jws-value");
        when(configService.getActiveSigningConfig()).thenReturn(Mono.just(ownKey()));
        when(kmsProvider.sign(any())).thenReturn(Mono.just(expected));
        doThrow(new IllegalStateException("audit down")).when(auditService)
                .auditSuccess(any(), any(), any(), any(), any());

        StepVerifier.create(signAs("kpmg")).expectNext(expected).verifyComplete();
    }

    @Test
    void sign_auditServiceThrowingOnFailure_keepsTheOriginalError() {
        when(configService.getActiveSigningConfig()).thenReturn(Mono.just(ownKey()));
        when(configService.reloadActiveSigningConfig()).thenReturn(Mono.just(ownKey()));
        when(kmsProvider.sign(any())).thenReturn(Mono.error(
                new KmsSigningException(SigningFailureReason.KEY_UNUSABLE, "disabled")));
        doThrow(new IllegalStateException("audit down")).when(auditService).auditFailure(any(), any(), any(), any());

        StepVerifier.create(signAs("kpmg"))
                .expectErrorSatisfies(e -> assertThat(e).isInstanceOf(KmsSigningException.class))
                .verify();
    }
}
