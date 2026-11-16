package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.SlidingWindow;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitPolicy;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.IdempotencyStore;
import es.in2.issuer.backend.shared.domain.spi.VolumeCounterStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApiRequestControlCleanupSchedulerTest {

    private static final Instant NOW = Instant.parse("2026-11-10T10:00:30Z");

    @Mock
    private TenantRegistryService tenantRegistryService;
    @Mock
    private IdempotencyStore idempotencyStore;
    @Mock
    private VolumeCounterStore volumeCounterStore;

    @Test
    void purge_everyTenant_expiredKeysAndTheBucketsOutOfTheWindow_skippingOneThatFails() {
        VolumeLimitPolicy policy = new VolumeLimitPolicy(new SlidingWindow(Duration.ofMinutes(1)),
                Arrays.stream(ApiOperation.values()).collect(Collectors.toMap(o -> o, o -> new VolumeLimitPolicy.Limits(1, 1))));
        ApiRequestControlCleanupScheduler scheduler = new ApiRequestControlCleanupScheduler(tenantRegistryService,
                idempotencyStore, volumeCounterStore, policy, Clock.fixed(NOW, ZoneOffset.UTC));
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("sandbox", "cgcom")));
        when(idempotencyStore.purgeExpired(NOW)).thenReturn(Mono.error(new IllegalStateException("down")), Mono.just(2L));
        when(volumeCounterStore.purgeBefore(Instant.parse("2026-11-10T09:59:30Z"))).thenReturn(Mono.just(5L));

        StepVerifier.create(scheduler.purge()).verifyComplete();

        verify(idempotencyStore, times(2)).purgeExpired(NOW);
        verify(volumeCounterStore, times(2)).purgeBefore(Instant.parse("2026-11-10T09:59:30Z"));
    }

    @Test
    void purge_withoutTenantRegistry_doesNotFail() {
        VolumeLimitPolicy policy = new VolumeLimitPolicy(new SlidingWindow(Duration.ofMinutes(1)),
                Map.of(ApiOperation.ISSUANCE, new VolumeLimitPolicy.Limits(1, 1), ApiOperation.REVOCATION,
                        new VolumeLimitPolicy.Limits(1, 1), ApiOperation.SEARCH, new VolumeLimitPolicy.Limits(1, 1),
                        ApiOperation.READ, new VolumeLimitPolicy.Limits(1, 1)));
        ApiRequestControlCleanupScheduler scheduler = new ApiRequestControlCleanupScheduler(tenantRegistryService,
                idempotencyStore, volumeCounterStore, policy, Clock.fixed(NOW, ZoneOffset.UTC));
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.error(new IllegalStateException("down")));

        StepVerifier.create(scheduler.purge()).verifyComplete();
    }
}
