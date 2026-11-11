package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.SlidingWindow;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitDecision;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitPolicy;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.spi.VolumeCounterStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VolumeLimitServiceImplTest {

    private static final Instant NOW = Instant.parse("2026-11-10T10:00:30Z");
    private static final String ORG = "VATES-A15456585";
    private static final String OVERRIDE_KEY = "issuer.volume_limit.issuance." + ORG;

    @Mock
    private VolumeCounterStore counterStore;
    @Mock
    private TenantConfigService tenantConfigService;

    private VolumeLimitServiceImpl service;

    @BeforeEach
    void setUp() {
        VolumeLimitPolicy policy = new VolumeLimitPolicy(new SlidingWindow(Duration.ofMinutes(1)), Map.of(
                ApiOperation.ISSUANCE, new VolumeLimitPolicy.Limits(300, 30),
                ApiOperation.REVOCATION, new VolumeLimitPolicy.Limits(300, 30),
                ApiOperation.SEARCH, new VolumeLimitPolicy.Limits(60, 10),
                ApiOperation.READ, new VolumeLimitPolicy.Limits(300, 30)));
        service = new VolumeLimitServiceImpl(policy, counterStore, tenantConfigService, Clock.fixed(NOW, ZoneOffset.UTC));
        lenient().when(counterStore.undo(anyString(), any())).thenReturn(Mono.empty());
    }

    private Mono<VolumeLimitDecision> check(ApiOperation operation, Requester requester) {
        return service.check(operation, requester).contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "sandbox"));
    }

    private void counted(long current) {
        when(counterStore.increment(anyString(), any(), any()))
                .thenReturn(Mono.just(Map.of(Instant.parse("2026-11-10T10:00:30Z"), current)));
    }

    @Test
    void check_aPerson_hasThePersonLimitAndNeverReadsTheOrganizationConfiguration() {
        counted(31);

        StepVerifier.create(check(ApiOperation.ISSUANCE, Requester.person(ORG, "pseudonym")))
                .assertNext(decision -> {
                    assertThat(decision.allowed()).isFalse();
                    assertThat(decision.limit()).isEqualTo(30);
                })
                .verifyComplete();
        verify(tenantConfigService, never()).getString(anyString());
    }

    @Test
    void check_aRejectedRequestIsTakenBack_anAllowedOneIsNot() {
        counted(31);
        StepVerifier.create(check(ApiOperation.ISSUANCE, Requester.person(ORG, "pseudonym")))
                .assertNext(decision -> assertThat(decision.allowed()).isFalse())
                .verifyComplete();
        verify(counterStore).undo(anyString(), eq(Instant.parse("2026-11-10T10:00:30Z")));

        counted(30);
        StepVerifier.create(check(ApiOperation.ISSUANCE, Requester.person(ORG, "other")))
                .assertNext(decision -> assertThat(decision.allowed()).isTrue())
                .verifyComplete();
        verify(counterStore, times(1)).undo(anyString(), any());
    }

    @Test
    void check_theSystemsOfAnOrganization_haveTheOrganizationLimit() {
        counted(300);
        when(tenantConfigService.getString(OVERRIDE_KEY)).thenReturn(Mono.empty());

        StepVerifier.create(check(ApiOperation.ISSUANCE, Requester.system(ORG)))
                .assertNext(decision -> {
                    assertThat(decision.allowed()).isTrue();
                    assertThat(decision.limit()).isEqualTo(300);
                })
                .verifyComplete();
    }

    @Test
    void check_eachOperationHasItsOwnLimit() {
        counted(11);

        StepVerifier.create(check(ApiOperation.SEARCH, Requester.person(ORG, "pseudonym")))
                .assertNext(decision -> assertThat(decision.limit()).isEqualTo(10))
                .verifyComplete();
    }

    @Test
    void check_supportRaisedTheLimitOfAnOrganization_itsSystemsUseIt() {
        counted(301);
        when(tenantConfigService.getString(OVERRIDE_KEY)).thenReturn(Mono.just(" 600 "));

        StepVerifier.create(check(ApiOperation.ISSUANCE, Requester.system(ORG)))
                .assertNext(decision -> {
                    assertThat(decision.allowed()).isTrue();
                    assertThat(decision.limit()).isEqualTo(600);
                })
                .verifyComplete();
    }

    @Test
    void check_aConfiguredLimitThatIsNotAPositiveNumber_keepsTheDefault() {
        counted(1);
        when(tenantConfigService.getString(OVERRIDE_KEY)).thenReturn(Mono.just("-5"));

        StepVerifier.create(check(ApiOperation.ISSUANCE, Requester.system(ORG)))
                .assertNext(decision -> assertThat(decision.limit()).isEqualTo(300))
                .verifyComplete();
    }

    @Test
    void check_anUnreadableConfiguration_keepsTheDefault() {
        counted(1);
        when(tenantConfigService.getString(OVERRIDE_KEY)).thenReturn(Mono.error(new IllegalStateException("db down")));

        StepVerifier.create(check(ApiOperation.ISSUANCE, Requester.system(ORG)))
                .assertNext(decision -> assertThat(decision.limit()).isEqualTo(300))
                .verifyComplete();
    }

    @Test
    void check_theOrganizationConfigurationIsReadOncePerCacheLifetime_evenWhenAbsent() {
        counted(1);
        when(tenantConfigService.getString(OVERRIDE_KEY)).thenReturn(Mono.empty());

        StepVerifier.create(check(ApiOperation.ISSUANCE, Requester.system(ORG))
                        .then(check(ApiOperation.ISSUANCE, Requester.system(ORG))))
                .expectNextCount(1)
                .verifyComplete();
        verify(tenantConfigService, times(1)).getString(OVERRIDE_KEY);
    }

    @Test
    void check_countsInTheCurrentBucketAndReadsTheLastMinute_underAKeyWithoutPersonalData() {
        counted(1);
        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);

        StepVerifier.create(check(ApiOperation.READ, Requester.person(ORG, "ana@example.org")))
                .expectNextCount(1)
                .verifyComplete();

        verify(counterStore).increment(key.capture(), any(), any());
        verify(counterStore).increment(anyString(),
                org.mockito.ArgumentMatchers.eq(Instant.parse("2026-11-10T10:00:30Z")),
                org.mockito.ArgumentMatchers.eq(Instant.parse("2026-11-10T09:59:30Z")));
        assertThat(key.getValue()).startsWith("read:").doesNotContain("ana").doesNotContain(ORG);
    }
}
