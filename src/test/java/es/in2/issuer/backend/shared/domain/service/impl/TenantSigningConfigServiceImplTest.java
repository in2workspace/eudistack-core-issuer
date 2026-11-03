package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Ticker;
import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantSigningConfigRepository;
import es.in2.issuer.backend.signing.domain.exception.SigningConfigurationChangedException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.service.OwnKeySigningConfigLoader;
import es.in2.issuer.backend.signing.domain.util.SigningConfigScope;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TenantSigningConfigServiceImplTest {

    @Mock
    private TenantSigningConfigRepository repository;

    @Mock
    private OwnKeySigningConfigLoader ownKeyLoader;

    private final AtomicLong nanos = new AtomicLong();
    private final Ticker ticker = nanos::get;
    private TenantSigningConfigServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new TenantSigningConfigServiceImpl(repository, new ObjectMapper(), ownKeyLoader,
                Duration.ofSeconds(30), ticker);
    }

    private static TenantSigningConfig qtspRow() {
        return qtspRow("cred-1");
    }

    private static TenantSigningConfig qtspRow(String credentialId) {
        return new TenantSigningConfig(UUID.randomUUID(), "digitel", "v2",
                "{\"url\":\"https://qtsp.test\",\"credentialId\":\"" + credentialId + "\",\"credentialPwd\":\"pwd\","
                        + "\"clientId\":\"cid\",\"clientSecret\":\"secret\",\"certCacheTtl\":\"PT10M\"}",
                null, null, "qtsp", "active");
    }

    private static TenantSigningConfig ownKeyRow() {
        return new TenantSigningConfig(UUID.randomUUID(), "aws-kms", null, null, null, null, "own_key", "active");
    }

    private Mono<ActiveSigningConfig> load(String tenant) {
        return service.getActiveSigningConfig().contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
    }

    @Test
    void getActiveSigningConfig_qtspRow_mapsToTheSameDtoAsBefore() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.just(qtspRow()));

        StepVerifier.create(load("t1"))
                .assertNext(config -> {
                    assertThat(config.modality()).isEqualTo(SigningModality.QTSP);
                    assertThat(config.ownKey()).isNull();
                    assertThat(config.qtsp()).isEqualTo(new RemoteSignatureDto(
                            "digitel", "v2", "https://qtsp.test", "https://qtsp.test", "sign-hash",
                            "cred-1", "pwd", "PT10M", "cid", "secret", "", "", "", "", ""));
                })
                .verifyComplete();
    }

    @Test
    void getActiveSigningConfig_onlyAsksForTheActiveRow() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc(any())).thenReturn(Mono.empty());

        StepVerifier.create(load("t1")).verifyComplete();

        verify(repository).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void getActiveSigningConfig_noActiveRow_isEmptyAndNotCached() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.empty());

        StepVerifier.create(load("t1")).verifyComplete();
        StepVerifier.create(load("t1")).verifyComplete();

        verify(repository, times(2)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void getActiveSigningConfig_ownKeyRow_isBuiltFromTheCertificateOfTheTenant() {
        var ownKey = new OwnKeySigningConfig("alias/own-key-abc", "ES256", List.of("MIIB-leaf"));
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.just(ownKeyRow()));
        when(ownKeyLoader.load("t1")).thenReturn(Mono.just(ownKey));

        StepVerifier.create(load("t1"))
                .assertNext(config -> {
                    assertThat(config.modality()).isEqualTo(SigningModality.OWN_KEY);
                    assertThat(config.qtsp()).isNull();
                    assertThat(config.ownKey()).isEqualTo(ownKey);
                })
                .verifyComplete();
    }

    @Test
    void getActiveSigningConfig_ownKeyCertificateUnusable_failsAndNothingIsCached() {
        var failure = new SigningException(SigningFailureReason.NO_CONFIGURATION, "no certificate");
        var ownKey = new OwnKeySigningConfig("alias/own-key-abc", "ES256", List.of("MIIB-leaf"));
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.just(ownKeyRow()));
        when(ownKeyLoader.load("t1")).thenReturn(Mono.error(failure)).thenReturn(Mono.just(ownKey));

        StepVerifier.create(load("t1")).expectErrorSatisfies(e -> assertThat(e).isSameAs(failure)).verify();
        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();

        verify(repository, times(2)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void getActiveSigningConfig_qtspRow_readsNoCertificate() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.just(qtspRow()));

        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();

        verifyNoInteractions(ownKeyLoader);
    }

    @Test
    void getActiveSigningConfig_unknownModality_failsWithNoConfiguration() {
        TenantSigningConfig row = qtspRow();
        var unknown = new TenantSigningConfig(row.id(), row.provider(), row.cscApiVersion(),
                row.providerSpecificConfig(), null, null, "hsm", "active");
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.just(unknown));

        StepVerifier.create(load("t1"))
                .expectErrorSatisfies(err -> assertThat(((SigningException) err).getReason())
                        .isEqualTo(SigningFailureReason.NO_CONFIGURATION))
                .verify();
    }

    @Test
    void getActiveSigningConfig_withinTtl_servesTheCachedConfig() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.just(qtspRow()));

        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();
        nanos.addAndGet(Duration.ofSeconds(29).toNanos());
        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();

        verify(repository, times(1)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void getActiveSigningConfig_afterTtl_readsTheRepositoryAgain() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(qtspRow("cred-1")))
                .thenReturn(Mono.just(qtspRow("cred-2")));

        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();
        nanos.addAndGet(Duration.ofSeconds(31).toNanos());

        StepVerifier.create(load("t1"))
                .assertNext(config -> assertThat(config.qtsp().credentialId()).isEqualTo("cred-2"))
                .verifyComplete();
        verify(repository, times(2)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void getActiveSigningConfig_cacheIsKeyedByTenant() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.just(qtspRow()));

        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();
        StepVerifier.create(load("t2")).expectNextCount(1).verifyComplete();

        verify(repository, times(2)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void cacheTtl_defaultIs5Minutes_andNonPositiveIsRejected() throws NoSuchMethodException {
        var ttl = TenantSigningConfigServiceImpl.class.getConstructor(
                        TenantSigningConfigRepository.class, ObjectMapper.class, OwnKeySigningConfigLoader.class,
                        Duration.class)
                .getParameters()[3].getAnnotation(org.springframework.beans.factory.annotation.Value.class);
        assertThat(ttl.value()).isEqualTo("${issuer.signing.config-cache-ttl:5m}");
        assertThat(org.springframework.boot.convert.ApplicationConversionService.getSharedInstance()
                .convert("5m", Duration.class)).isEqualTo(Duration.ofMinutes(5));
        ObjectMapper objectMapper = new ObjectMapper();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new TenantSigningConfigServiceImpl(
                        repository, objectMapper, ownKeyLoader, Duration.ZERO, ticker))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void reloadActiveSigningConfig_discardsTheCachedConfigurationOfTheTenant() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(qtspRow("cred-1")))
                .thenReturn(Mono.just(qtspRow("cred-2")));

        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();
        StepVerifier.create(service.reloadActiveSigningConfig()
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "t1")))
                .assertNext(config -> assertThat(config.qtsp().credentialId()).isEqualTo("cred-2"))
                .verifyComplete();
        StepVerifier.create(load("t1"))
                .assertNext(config -> assertThat(config.qtsp().credentialId()).isEqualTo("cred-2"))
                .verifyComplete();

        verify(repository, times(2)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    // --- One configuration per request ---

    private static <T> Mono<T> inTenant(Mono<T> mono, String tenant) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
    }

    private static String credentialOf(ActiveSigningConfig config) {
        return config.qtsp().credentialId();
    }

    @Test
    void withinScope_laterReadsReuseTheFirst_evenWhenTheCacheExpiresInBetween() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(qtspRow("cred-1")))
                .thenReturn(Mono.just(qtspRow("cred-2")));

        Mono<List<ActiveSigningConfig>> twoReads = SigningConfigScope.run(() -> service.getActiveSigningConfig()
                .flatMap(first -> {
                    nanos.addAndGet(Duration.ofSeconds(31).toNanos());
                    return service.getActiveSigningConfig().map(second -> List.of(first, second));
                }));

        StepVerifier.create(inTenant(twoReads, "t1"))
                .assertNext(reads -> {
                    assertThat(reads.get(0).qtsp().credentialId()).isEqualTo("cred-1");
                    assertThat(reads.get(1)).isSameAs(reads.get(0));
                })
                .verifyComplete();
        verify(repository, times(1)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void withinScope_eachTenantKeepsItsOwnConfiguration() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(qtspRow("cred-1")))
                .thenReturn(Mono.just(qtspRow("cred-2")));

        Mono<List<String>> reads = SigningConfigScope.run(() -> inTenant(service.getActiveSigningConfig(), "t1")
                .flatMap(t1 -> inTenant(service.getActiveSigningConfig(), "t2")
                        .flatMap(t2 -> inTenant(service.getActiveSigningConfig(), "t1")
                                .map(t1Again -> List.of(credentialOf(t1), credentialOf(t2), credentialOf(t1Again))))));

        StepVerifier.create(reads)
                .assertNext(credentials -> assertThat(credentials).containsExactly("cred-1", "cred-2", "cred-1"))
                .verifyComplete();
    }

    @Test
    void withinScope_reloadFindingAnotherConfiguration_failsAndTheScopeRunsAgainWithTheNewOne() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(qtspRow("cred-1")))
                .thenReturn(Mono.just(qtspRow("cred-2")));
        List<Throwable> reloadErrors = new ArrayList<>();

        Mono<String> request = SigningConfigScope.run(() -> service.getActiveSigningConfig()
                .flatMap(payloadConfig -> service.reloadActiveSigningConfig()
                        .doOnError(reloadErrors::add)
                        .map(signingConfig -> {
                            assertThat(signingConfig).isEqualTo(payloadConfig);
                            return credentialOf(signingConfig);
                        })));

        StepVerifier.create(inTenant(request, "t1"))
                .expectNext("cred-2")
                .verifyComplete();
        assertThat(reloadErrors).singleElement().isInstanceOf(SigningConfigurationChangedException.class);
        // First run: read and reload. Second run: the read hits the refreshed cache, the reload reads again.
        verify(repository, times(3)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void withinScope_reloadFindingTheSameConfiguration_returnsIt() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(qtspRow("cred-1")));

        Mono<Boolean> request = SigningConfigScope.run(() -> service.getActiveSigningConfig()
                .flatMap(payloadConfig -> service.reloadActiveSigningConfig().map(payloadConfig::equals)));

        StepVerifier.create(inTenant(request, "t1")).expectNext(true).verifyComplete();
        verify(repository, times(2)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void withinScope_reloadFindingNoConfiguration_isEmpty() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(qtspRow("cred-1")))
                .thenReturn(Mono.empty());

        Mono<ActiveSigningConfig> request = SigningConfigScope.run(() -> service.getActiveSigningConfig()
                .then(service.reloadActiveSigningConfig()));

        StepVerifier.create(inTenant(request, "t1")).verifyComplete();
    }
}
