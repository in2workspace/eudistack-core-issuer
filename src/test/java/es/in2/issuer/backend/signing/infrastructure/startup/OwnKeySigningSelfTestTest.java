package es.in2.issuer.backend.signing.infrastructure.startup;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.infrastructure.adapter.KmsOwnKeySigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningAuditor;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import es.in2.issuer.backend.signing.domain.util.SigningFailureReasons;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.SigningSelfTestProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class OwnKeySigningSelfTestTest {

    private final TenantRegistryService registry = mock(TenantRegistryService.class);
    private final TenantSigningConfigService configService = mock(TenantSigningConfigService.class);
    private final KmsOwnKeySigningProvider kmsProvider = mock(KmsOwnKeySigningProvider.class);
    private final SigningAuditor auditor = mock(SigningAuditor.class);
    private final KmsSigningProperties kmsProperties = new KmsSigningProperties(false, null, null,
            Duration.ofSeconds(10), 3, Duration.ofSeconds(1), Duration.ofSeconds(5));
    private final Logger logger = (Logger) LoggerFactory.getLogger(OwnKeySigningSelfTest.class);
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();

    @BeforeEach
    void attachAppender() {
        logs.start();
        logger.addAppender(logs);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(logs);
    }

    /** The stored leaf of {@link #ownKey()} is valid until 2099-01-01. */
    private static final OwnKeyTestPki PKI = new OwnKeyTestPki();
    private static final Clock NOW = Clock.fixed(Instant.parse("2026-06-01T00:00:00Z"), ZoneOffset.UTC);

    private OwnKeySigningSelfTest selfTest(boolean enabled) {
        return selfTest(new SigningSelfTestProperties(enabled, Duration.ofSeconds(5), Duration.ofDays(30)), NOW);
    }

    private OwnKeySigningSelfTest selfTest(SigningSelfTestProperties properties, Clock clock) {
        return new OwnKeySigningSelfTest(registry, configService, kmsProvider, auditor, properties, kmsProperties,
                clock);
    }

    private static OwnKeySigningConfig ownKey() {
        try {
            return new OwnKeySigningConfig("arn:aws:kms:eu-west-1:111122223333:key/secret-ref", "ES256",
                    List.of(Base64.getEncoder().encodeToString(PKI.validP256Leaf().certificate().getEncoded())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ActiveSigningConfig qtsp() {
        return ActiveSigningConfig.qtsp(new RemoteSignatureDto("p", "1", "u", "a", "sign-hash", "c", "pw",
                null, null, null, null, null, null, null, null));
    }

    /** The config service answers per tenant read from the Reactor context, like the real one. */
    private void configsByTenant(Map<String, ActiveSigningConfig> configs) {
        when(configService.getActiveSigningConfig()).thenReturn(Mono.deferContextual(ctx ->
                Mono.justOrEmpty(configs.get(ctx.<String>get(TENANT_DOMAIN_CONTEXT_KEY)))));
    }

    private List<String> messages(Level level) {
        return logs.list.stream().filter(e -> e.getLevel() == level).map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Test
    void run_ownKeyTenantsOkAndFailing_bothHandled_andNoErrorEscapes() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("good", "bad")));
        configsByTenant(Map.of(
                "good", ActiveSigningConfig.ownKey(ownKey()),
                "bad", ActiveSigningConfig.ownKey(ownKey())));
        Set<String> probed = new HashSet<>();
        when(kmsProvider.sign(any(SigningRequest.class)))
                .thenReturn(Mono.deferContextual(ctx -> {
                    String tenant = ctx.get(TENANT_DOMAIN_CONTEXT_KEY);
                    probed.add(tenant);
                    return "bad".equals(tenant)
                            ? Mono.<SigningResult>error(new SigningException(SigningFailureReason.KEY_UNUSABLE, "disabled"))
                            : Mono.just(new SigningResult(SigningType.JADES, "jws-value"));
                }));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        assertThat(probed).containsExactlyInAnyOrder("good", "bad");
        assertThat(messages(Level.INFO)).containsExactly("own-key signing self-test passed tenant=good");
        assertThat(messages(Level.WARN))
                .containsExactly("own-key signing self-test failed tenant=bad reason=KEY_UNUSABLE");
        var good = ArgumentCaptor.forClass(SigningAuditor.Attempt.class);
        verify(auditor).success(eq(SigningAuditor.SELF_TEST_EVENT), good.capture());
        assertThat(good.getValue().tenant()).isEqualTo("good");
        assertThat(good.getValue().modality()).isEqualTo("own_key");
        assertThat(good.getValue().provider()).isEqualTo("aws-kms");
        var bad = ArgumentCaptor.forClass(SigningAuditor.Attempt.class);
        var error = ArgumentCaptor.forClass(Throwable.class);
        verify(auditor).failure(eq(SigningAuditor.SELF_TEST_EVENT), bad.capture(), error.capture());
        assertThat(bad.getValue().tenant()).isEqualTo("bad");
        assertThat(SigningFailureReasons.of(error.getValue())).isEqualTo(SigningFailureReason.KEY_UNUSABLE);
        assertThat(logs.list).noneMatch(e -> e.getFormattedMessage().contains("secret-ref")
                || e.getFormattedMessage().contains("jws-value")
                || e.getFormattedMessage().contains("probe"));
    }

    @Test
    void run_probeIsAFixedJadesPayloadWithJwtTyp() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("t")));
        configsByTenant(Map.of("t", ActiveSigningConfig.ownKey(ownKey())));
        when(kmsProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "x")));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        var captor = ArgumentCaptor.forClass(SigningRequest.class);
        verify(kmsProvider).sign(captor.capture());
        assertThat(captor.getValue().ownKey()).isEqualTo(ownKey());
        assertThat(captor.getValue().type()).isEqualTo(SigningType.JADES);
        assertThat(captor.getValue().typ()).isEqualTo("JWT");
        assertThat(captor.getValue().data()).isEqualTo(OwnKeySigningSelfTest.PROBE_PAYLOAD);
    }

    @Test
    void run_qtspTenant_isSkipped_andProviderNeverCalled() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("q")));
        configsByTenant(Map.of("q", qtsp()));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        verifyNoInteractions(kmsProvider, auditor);
        assertThat(logs.list).isEmpty();
    }

    @Test
    void run_tenantListingFails_completesWithoutError() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.error(new IllegalStateException("db down")));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        assertThat(messages(Level.WARN)).hasSize(1);
    }

    @Test
    void run_tenantListingThrowsSynchronously_completesWithoutError() {
        when(registry.getActiveTenantSchemas()).thenThrow(new IllegalStateException("boom"));

        StepVerifier.create(selfTest(true).run()).verifyComplete();
    }

    @Test
    void run_configReadFailsForOneTenant_otherTenantsStillProbed() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("broken", "ok")));
        when(configService.getActiveSigningConfig()).thenReturn(Mono.deferContextual(ctx ->
                "broken".equals(ctx.get(TENANT_DOMAIN_CONTEXT_KEY))
                        ? Mono.<ActiveSigningConfig>error(
                                new SigningException(SigningFailureReason.NO_CONFIGURATION, "corrupt"))
                        : Mono.just(ActiveSigningConfig.ownKey(ownKey()))));
        when(kmsProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "x")));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        assertThat(messages(Level.WARN))
                .containsExactly("own-key signing self-test failed tenant=broken reason=NO_CONFIGURATION");
        assertThat(messages(Level.INFO)).containsExactly("own-key signing self-test passed tenant=ok");
    }

    @Test
    void run_slowProbe_timesOutAsFailure_withoutError() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("slow")));
        configsByTenant(Map.of("slow", ActiveSigningConfig.ownKey(ownKey())));
        when(kmsProvider.sign(any())).thenReturn(Mono.never());
        var slowSelfTest = selfTest(new SigningSelfTestProperties(true, Duration.ofMillis(50), Duration.ofDays(30)), NOW);

        StepVerifier.create(slowSelfTest.run()).verifyComplete();

        assertThat(messages(Level.WARN))
                .containsExactly("own-key signing self-test failed tenant=slow reason=PROVIDER_UNAVAILABLE");
        var error = ArgumentCaptor.forClass(Throwable.class);
        verify(auditor).failure(eq(SigningAuditor.SELF_TEST_EVENT), any(), error.capture());
        assertThat(SigningFailureReasons.of(error.getValue())).isEqualTo(SigningFailureReason.PROVIDER_UNAVAILABLE);
    }

    @Test
    void tenantTimeout_unset_coversTheWorstKmsCallWithItsRetries() {
        var derived = selfTest(new SigningSelfTestProperties(true, null, Duration.ofDays(30)), NOW);

        // 4 attempts of 10 s, 3 waits of at most 5 s, plus the 5 s margin.
        assertThat(kmsProperties.worstCaseSigningDuration()).isEqualTo(Duration.ofSeconds(55));
        assertThat(derived.tenantTimeout()).isEqualTo(Duration.ofSeconds(60));
        assertThat(selfTest(true).tenantTimeout()).isEqualTo(Duration.ofSeconds(5));
    }

    @Test
    void onApplicationReady_everyDependencyFailing_neverThrows() {
        when(registry.getActiveTenantSchemas()).thenThrow(new IllegalStateException("boom"));

        assertDoesNotThrow(() -> selfTest(true).onApplicationReady());
    }

    @Test
    void onApplicationReady_disabled_runsNothing() {
        selfTest(false).onApplicationReady();

        verifyNoInteractions(registry, configService, kmsProvider, auditor);
    }

    @Test
    void properties_nonPositiveTimeout_isRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new SigningSelfTestProperties(true, Duration.ZERO, Duration.ofDays(30)));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningSelfTestProperties(true, null, Duration.ofDays(-1)));
    }

    @Test
    void run_auditorThrowing_isSwallowed() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("t")));
        configsByTenant(Map.of("t", ActiveSigningConfig.ownKey(ownKey())));
        when(kmsProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "x")));
        doThrow(new IllegalStateException("audit down")).when(auditor).success(any(), any());

        StepVerifier.create(selfTest(true).run()).verifyComplete();
    }

    @Test
    void run_tenantWithoutActiveConfiguration_isReportedAsNoConfiguration() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("empty", "q")));
        configsByTenant(Map.of("q", qtsp()));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        assertThat(messages(Level.WARN))
                .containsExactly("signing self-test: no active signing configuration tenant=empty");
        var attempt = ArgumentCaptor.forClass(SigningAuditor.Attempt.class);
        var error = ArgumentCaptor.forClass(Throwable.class);
        verify(auditor).failure(eq(SigningAuditor.SELF_TEST_EVENT), attempt.capture(), error.capture());
        assertThat(attempt.getValue().tenant()).isEqualTo("empty");
        assertThat(attempt.getValue().modality()).isEqualTo(SigningAuditor.UNKNOWN);
        assertThat(attempt.getValue().provider()).isEqualTo(SigningAuditor.UNKNOWN);
        assertThat(SigningFailureReasons.of(error.getValue())).isEqualTo(SigningFailureReason.NO_CONFIGURATION);
        verifyNoInteractions(kmsProvider);
    }

    @Test
    void run_certificateExpiringWithinTheWarningWindow_logsAWarning() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("cgcom")));
        configsByTenant(Map.of("cgcom", ActiveSigningConfig.ownKey(ownKey())));
        when(kmsProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "x")));
        var twelveDaysBefore = Clock.fixed(Instant.parse("2098-12-20T00:00:00Z"), ZoneOffset.UTC);

        StepVerifier.create(selfTest(new SigningSelfTestProperties(true, Duration.ofSeconds(5), Duration.ofDays(30)),
                twelveDaysBefore).run()).verifyComplete();

        assertThat(messages(Level.WARN)).containsExactly(
                "own-key signing certificate expires soon tenant=cgcom notAfter=2099-01-01T00:00:00Z daysLeft=12");
        assertThat(messages(Level.INFO)).containsExactly("own-key signing self-test passed tenant=cgcom");
    }

    @Test
    void run_certificateExpiringAfterTheWarningWindow_logsNoWarning() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("cgcom")));
        configsByTenant(Map.of("cgcom", ActiveSigningConfig.ownKey(ownKey())));
        when(kmsProvider.sign(any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "x")));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        assertThat(messages(Level.WARN)).isEmpty();
    }
}
