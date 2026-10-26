package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Ticker;
import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantSigningConfigRepository;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
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
    private TenantSigningConfigServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new TenantSigningConfigServiceImpl(repository, new ObjectMapper(),
                Duration.ofSeconds(30), ticker);
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
                        TenantSigningConfigRepository.class, ObjectMapper.class, Duration.class)
                .getParameters()[2].getAnnotation(org.springframework.beans.factory.annotation.Value.class);
        assertThat(ttl.value()).isEqualTo("${issuer.signing.config-cache-ttl:5m}");
        assertThat(org.springframework.boot.convert.ApplicationConversionService.getSharedInstance()
                .convert("5m", Duration.class)).isEqualTo(Duration.ofMinutes(5));
        ObjectMapper objectMapper = new ObjectMapper();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new TenantSigningConfigServiceImpl(
                        repository, objectMapper, Duration.ZERO, ticker))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
