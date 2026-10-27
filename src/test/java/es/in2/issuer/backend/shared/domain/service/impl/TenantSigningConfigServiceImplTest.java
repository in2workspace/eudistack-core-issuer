package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Ticker;
import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantSigningConfigRepository;
import es.in2.issuer.backend.signing.domain.exception.KmsSigningException;
import es.in2.issuer.backend.signing.domain.exception.SigningConfigurationChangedException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.domain.util.SigningConfigScope;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TenantSigningConfigServiceImplTest {

    private static final String KMS_REF = "arn:aws:kms:eu-west-1:111122223333:key/k";

    @Mock
    private TenantSigningConfigRepository repository;

    private final AtomicLong nanos = new AtomicLong();
    private final Ticker ticker = nanos::get;
    private final KmsSigningPort kms = mock(KmsSigningPort.class);
    private TenantSigningConfigServiceImpl service;

    private static ObjectProvider<KmsSigningPort> kmsProvider(KmsSigningPort port) {
        @SuppressWarnings("unchecked")
        ObjectProvider<KmsSigningPort> provider = mock(ObjectProvider.class);
        lenient().when(provider.getIfAvailable()).thenReturn(port);
        return provider;
    }

    @BeforeEach
    void setUp() {
        lenient().when(kms.findTenantTag(KMS_REF)).thenReturn(Mono.just("t1"));
        service = new TenantSigningConfigServiceImpl(repository, new ObjectMapper(),
                Duration.ofSeconds(30), kmsProvider(kms), ticker);
    }

    private static TenantSigningConfig qtspRow() {
        return new TenantSigningConfig(UUID.randomUUID(), "digitel", "v2",
                "{\"url\":\"https://qtsp.test\",\"credentialId\":\"cred-1\",\"credentialPwd\":\"pwd\","
                        + "\"clientId\":\"cid\",\"clientSecret\":\"secret\",\"certCacheTtl\":\"PT10M\"}",
                null, null, "qtsp", "active", null, null,
                null, null, null, null, null);
    }

    private static TenantSigningConfig ownKeyRow(String algorithm, String chainJson, String keyRef) {
        return new TenantSigningConfig(UUID.randomUUID(), "aws-kms", null, null, null, null,
                "own_key", "active", null, null,
                keyRef, algorithm, chainJson, null, null);
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
    void getActiveSigningConfig_ownKeyRow_mapsChainWithoutQtspDto() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\",\"MIIB-intermediate\"]", KMS_REF)));

        StepVerifier.create(load("t1"))
                .assertNext(config -> {
                    assertThat(config.modality()).isEqualTo(SigningModality.OWN_KEY);
                    assertThat(config.qtsp()).isNull();
                    var ownKey = config.ownKey();
                    assertThat(ownKey.kmsKeyRef()).isEqualTo(KMS_REF);
                    assertThat(ownKey.algorithm()).isEqualTo("ES256");
                    assertThat(ownKey.certificateChain()).containsExactly("MIIB-leaf", "MIIB-intermediate");
                })
                .verifyComplete();
    }

    @Test
    void getActiveSigningConfig_ownKeyRow_keepsTheTenantTagOfTheKeyInTheConfiguration() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)));

        StepVerifier.create(load("t1"))
                .assertNext(config -> assertThat(config.ownKey().keyTenantTag()).isEqualTo("t1"))
                .verifyComplete();
    }

    @Test
    void getActiveSigningConfig_keyWithoutTenantTag_loadsWithNoTag() {
        when(kms.findTenantTag(KMS_REF)).thenReturn(Mono.empty());
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)));

        StepVerifier.create(load("t1"))
                .assertNext(config -> assertThat(config.ownKey().keyTenantTag()).isNull())
                .verifyComplete();
    }

    @Test
    void getActiveSigningConfig_tagsAreReadOnceWhileTheConfigurationIsCached() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)));

        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();
        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();

        verify(kms, times(1)).findTenantTag(KMS_REF);
    }

    @Test
    void getActiveSigningConfig_readingTheTagsFails_theLoadFailsAndNothingIsCached() {
        var failure = new KmsSigningException(SigningFailureReason.PROVIDER_UNAVAILABLE, "kms down");
        when(kms.findTenantTag(KMS_REF)).thenReturn(Mono.error(failure)).thenReturn(Mono.just("t1"));
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)));

        StepVerifier.create(load("t1")).expectErrorSatisfies(e -> assertThat(e).isSameAs(failure)).verify();
        StepVerifier.create(load("t1"))
                .assertNext(config -> assertThat(config.ownKey().keyTenantTag()).isEqualTo("t1"))
                .verifyComplete();

        verify(repository, times(2)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void getActiveSigningConfig_kmsSigningDisabled_readsNoTagsAndLoadsWithNoTag() {
        service = new TenantSigningConfigServiceImpl(repository, new ObjectMapper(),
                Duration.ofSeconds(30), kmsProvider(null), ticker);
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)));

        StepVerifier.create(load("t1"))
                .assertNext(config -> assertThat(config.ownKey().keyTenantTag()).isNull())
                .verifyComplete();
        verify(kms, never()).findTenantTag(any());
    }

    @Test
    void getActiveSigningConfig_qtspRow_readsNoTags() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.just(qtspRow()));

        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();

        verify(kms, never()).findTenantTag(any());
    }

    @Test
    void withinScope_reloadFindingTheKeyRetagged_isAChangedConfiguration() {
        when(kms.findTenantTag(KMS_REF)).thenReturn(Mono.just("t1")).thenReturn(Mono.just("t2"));
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)));

        List<Throwable> reloadErrors = new ArrayList<>();

        Mono<ActiveSigningConfig> request = SigningConfigScope.run(() -> service.getActiveSigningConfig()
                .then(service.reloadActiveSigningConfig().doOnError(reloadErrors::add)));

        // The scope runs the request again, this time with the configuration that carries the new tag.
        StepVerifier.create(inTenant(request, "t1"))
                .assertNext(config -> assertThat(config.ownKey().keyTenantTag()).isEqualTo("t2"))
                .verifyComplete();
        assertThat(reloadErrors).singleElement().isInstanceOf(SigningConfigurationChangedException.class);
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
    void getActiveSigningConfig_invalidOwnKeyRows_failWithNoConfiguration() {
        List<TenantSigningConfig> invalidRows = List.of(
                ownKeyRow("ES256", "[]", KMS_REF),
                ownKeyRow("ES256", null, KMS_REF),
                ownKeyRow("ES256", "{\"not\":\"an array\"}", KMS_REF),
                ownKeyRow("ES256", "not json", KMS_REF),
                ownKeyRow("ES256", "[\"\"]", KMS_REF),
                ownKeyRow("RS256", "[\"MIIB-leaf\"]", KMS_REF),
                ownKeyRow("ES256", "[\"MIIB-leaf\"]", " "));

        for (TenantSigningConfig row : invalidRows) {
            when(repository.findFirstByStatusOrderByCreatedAtDesc("active")).thenReturn(Mono.just(row));

            StepVerifier.create(load("t1"))
                    .expectErrorSatisfies(err -> {
                        assertThat(err).isInstanceOf(SigningException.class);
                        assertThat(((SigningException) err).getReason()).isEqualTo(SigningFailureReason.NO_CONFIGURATION);
                        assertThat(err.getMessage()).doesNotContain(KMS_REF);
                    })
                    .verify();
        }
    }

    @Test
    void getActiveSigningConfig_unknownModality_failsWithNoConfiguration() {
        TenantSigningConfig row = qtspRow();
        var unknown = new TenantSigningConfig(row.id(), row.provider(), row.cscApiVersion(),
                row.providerSpecificConfig(), null, null, "hsm", "active", null, null,
                null, null, null, null, null);
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
                .thenReturn(Mono.just(qtspRow()))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)));

        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();
        nanos.addAndGet(Duration.ofSeconds(31).toNanos());

        StepVerifier.create(load("t1"))
                .assertNext(config -> assertThat(config.modality()).isEqualTo(SigningModality.OWN_KEY))
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
                        TenantSigningConfigRepository.class, ObjectMapper.class, Duration.class, ObjectProvider.class)
                .getParameters()[2].getAnnotation(org.springframework.beans.factory.annotation.Value.class);
        assertThat(ttl.value()).isEqualTo("${issuer.signing.config-cache-ttl:5m}");
        assertThat(org.springframework.boot.convert.ApplicationConversionService.getSharedInstance()
                .convert("5m", Duration.class)).isEqualTo(Duration.ofMinutes(5));
        ObjectMapper objectMapper = new ObjectMapper();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new TenantSigningConfigServiceImpl(
                        repository, objectMapper, Duration.ZERO, kmsProvider(kms), ticker))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void reloadActiveSigningConfig_discardsTheCachedConfigurationOfTheTenant() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)))
                .thenReturn(Mono.just(qtspRow()));

        StepVerifier.create(load("t1")).expectNextCount(1).verifyComplete();
        StepVerifier.create(service.reloadActiveSigningConfig()
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "t1")))
                .assertNext(config -> assertThat(config.modality()).isEqualTo(SigningModality.QTSP))
                .verifyComplete();
        StepVerifier.create(load("t1"))
                .assertNext(config -> assertThat(config.modality()).isEqualTo(SigningModality.QTSP))
                .verifyComplete();

        verify(repository, times(2)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    // --- One configuration per request (EUD-289 M4) ---

    private static <T> Mono<T> inTenant(Mono<T> mono, String tenant) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
    }

    @Test
    void withinScope_laterReadsReuseTheFirst_evenWhenTheCacheExpiresInBetween() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)))
                .thenReturn(Mono.just(qtspRow()));

        Mono<List<ActiveSigningConfig>> twoReads = SigningConfigScope.run(() -> service.getActiveSigningConfig()
                .flatMap(first -> {
                    nanos.addAndGet(Duration.ofSeconds(31).toNanos());
                    return service.getActiveSigningConfig().map(second -> List.of(first, second));
                }));

        StepVerifier.create(inTenant(twoReads, "t1"))
                .assertNext(reads -> {
                    assertThat(reads.get(0).modality()).isEqualTo(SigningModality.OWN_KEY);
                    assertThat(reads.get(1)).isSameAs(reads.get(0));
                })
                .verifyComplete();
        verify(repository, times(1)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void withinScope_eachTenantKeepsItsOwnConfiguration() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)))
                .thenReturn(Mono.just(qtspRow()));

        Mono<List<SigningModality>> reads = SigningConfigScope.run(() -> inTenant(service.getActiveSigningConfig(), "t1")
                .flatMap(t1 -> inTenant(service.getActiveSigningConfig(), "t2")
                        .flatMap(t2 -> inTenant(service.getActiveSigningConfig(), "t1")
                                .map(t1Again -> List.of(t1.modality(), t2.modality(), t1Again.modality())))));

        StepVerifier.create(reads)
                .assertNext(modalities -> assertThat(modalities)
                        .containsExactly(SigningModality.OWN_KEY, SigningModality.QTSP, SigningModality.OWN_KEY))
                .verifyComplete();
    }

    @Test
    void withinScope_reloadFindingAnotherConfiguration_failsAndTheScopeRunsAgainWithTheNewOne() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)))
                .thenReturn(Mono.just(qtspRow()));
        List<Throwable> reloadErrors = new ArrayList<>();

        Mono<SigningModality> request = SigningConfigScope.run(() -> service.getActiveSigningConfig()
                .flatMap(payloadConfig -> service.reloadActiveSigningConfig()
                        .doOnError(reloadErrors::add)
                        .map(signingConfig -> {
                            assertThat(signingConfig).isEqualTo(payloadConfig);
                            return signingConfig.modality();
                        })));

        StepVerifier.create(inTenant(request, "t1"))
                .expectNext(SigningModality.QTSP)
                .verifyComplete();
        assertThat(reloadErrors).singleElement().isInstanceOf(SigningConfigurationChangedException.class);
        // First run: read and reload. Second run: the read hits the refreshed cache, the reload reads again.
        verify(repository, times(3)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void withinScope_reloadFindingTheSameConfiguration_returnsIt() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)));

        Mono<Boolean> request = SigningConfigScope.run(() -> service.getActiveSigningConfig()
                .flatMap(payloadConfig -> service.reloadActiveSigningConfig().map(payloadConfig::equals)));

        StepVerifier.create(inTenant(request, "t1")).expectNext(true).verifyComplete();
        verify(repository, times(2)).findFirstByStatusOrderByCreatedAtDesc("active");
    }

    @Test
    void withinScope_reloadFindingNoConfiguration_isEmpty() {
        when(repository.findFirstByStatusOrderByCreatedAtDesc("active"))
                .thenReturn(Mono.just(ownKeyRow("ES256", "[\"MIIB-leaf\"]", KMS_REF)))
                .thenReturn(Mono.empty());

        Mono<ActiveSigningConfig> request = SigningConfigScope.run(() -> service.getActiveSigningConfig()
                .then(service.reloadActiveSigningConfig()));

        StepVerifier.create(inTenant(request, "t1")).verifyComplete();
    }
}
