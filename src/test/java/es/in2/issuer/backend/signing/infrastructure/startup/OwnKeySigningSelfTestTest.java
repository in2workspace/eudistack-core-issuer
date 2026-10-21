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
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.infrastructure.properties.SigningSelfTestProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class OwnKeySigningSelfTestTest {

    private final TenantRegistryService registry = mock(TenantRegistryService.class);
    private final TenantSigningConfigService configService = mock(TenantSigningConfigService.class);
    private final KmsOwnKeySigningProvider kmsProvider = mock(KmsOwnKeySigningProvider.class);
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

    private OwnKeySigningSelfTest selfTest(boolean enabled) {
        return new OwnKeySigningSelfTest(registry, configService, kmsProvider,
                new SigningSelfTestProperties(enabled, Duration.ofSeconds(5)));
    }

    private static OwnKeySigningConfig ownKey() {
        return new OwnKeySigningConfig("arn:aws:kms:eu-west-1:111122223333:key/secret-ref", "ES256",
                List.of("MIIB-leaf"), null, null, null, null, null, "a".repeat(64));
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
        when(kmsProvider.sign(any(SigningRequest.class), any(OwnKeySigningConfig.class)))
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
        assertThat(logs.list).noneMatch(e -> e.getFormattedMessage().contains("secret-ref")
                || e.getFormattedMessage().contains("jws-value")
                || e.getFormattedMessage().contains("probe"));
    }

    @Test
    void run_probeIsAFixedJadesPayloadWithJwtTyp() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("t")));
        configsByTenant(Map.of("t", ActiveSigningConfig.ownKey(ownKey())));
        when(kmsProvider.sign(any(), any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "x")));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        var captor = ArgumentCaptor.forClass(SigningRequest.class);
        verify(kmsProvider).sign(captor.capture(), any());
        assertThat(captor.getValue().type()).isEqualTo(SigningType.JADES);
        assertThat(captor.getValue().typ()).isEqualTo("JWT");
        assertThat(captor.getValue().data()).isEqualTo(OwnKeySigningSelfTest.PROBE_PAYLOAD);
    }

    @Test
    void run_qtspTenant_isSkipped_andProviderNeverCalled() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("q")));
        configsByTenant(Map.of("q", qtsp()));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        verifyNoInteractions(kmsProvider);
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
        when(kmsProvider.sign(any(), any())).thenReturn(Mono.just(new SigningResult(SigningType.JADES, "x")));

        StepVerifier.create(selfTest(true).run()).verifyComplete();

        assertThat(messages(Level.WARN))
                .containsExactly("own-key signing self-test failed tenant=broken reason=NO_CONFIGURATION");
        assertThat(messages(Level.INFO)).containsExactly("own-key signing self-test passed tenant=ok");
    }

    @Test
    void run_slowProbe_timesOutAsFailure_withoutError() {
        when(registry.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("slow")));
        configsByTenant(Map.of("slow", ActiveSigningConfig.ownKey(ownKey())));
        when(kmsProvider.sign(any(), any())).thenReturn(Mono.never());
        var slowSelfTest = new OwnKeySigningSelfTest(registry, configService, kmsProvider,
                new SigningSelfTestProperties(true, Duration.ofMillis(50)));

        StepVerifier.create(slowSelfTest.run()).verifyComplete();

        assertThat(messages(Level.WARN)).hasSize(1);
    }

    @Test
    void onApplicationReady_everyDependencyFailing_neverThrows() {
        when(registry.getActiveTenantSchemas()).thenThrow(new IllegalStateException("boom"));

        assertDoesNotThrow(() -> selfTest(true).onApplicationReady());
    }

    @Test
    void onApplicationReady_disabled_runsNothing() {
        selfTest(false).onApplicationReady();

        verifyNoInteractions(registry, configService, kmsProvider);
    }

    @Test
    void properties_nonPositiveTimeout_isRejected() {
        assertThrows(IllegalArgumentException.class, () -> new SigningSelfTestProperties(true, Duration.ZERO));
    }
}
