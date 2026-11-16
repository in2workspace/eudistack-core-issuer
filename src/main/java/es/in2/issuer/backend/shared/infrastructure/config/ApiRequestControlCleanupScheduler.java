package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitPolicy;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.IdempotencyStore;
import es.in2.issuer.backend.shared.domain.spi.VolumeCounterStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Deletes, in every tenant, the idempotency keys whose retention ended and the volume counters of the windows
 * that no longer count (EUD-269). Every instance may run it at once: it only deletes what already expired.
 * A tenant that fails is skipped and retried on the next run.
 */
@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class ApiRequestControlCleanupScheduler {

    private final TenantRegistryService tenantRegistryService;
    private final IdempotencyStore idempotencyStore;
    private final VolumeCounterStore volumeCounterStore;
    private final VolumeLimitPolicy volumeLimitPolicy;
    private final Clock clock;

    @Scheduled(cron = "${issuer.api.request-control-cleanup-cron:0 */10 * * * *}")
    public Mono<Void> purge() {
        Instant now = clock.instant();
        // The decision reads the buckets of the window: anything older no longer counts.
        Instant countersBefore = volumeLimitPolicy.window().oldestCountedBucket(now);
        return tenantRegistryService.getActiveTenantSchemas()
                .flatMapMany(Flux::fromIterable)
                .concatMap(tenant -> Mono.zip(idempotencyStore.purgeExpired(now), volumeCounterStore.purgeBefore(countersBefore))
                        .doOnNext(purged -> {
                            if (purged.getT1() + purged.getT2() > 0) {
                                log.info("Request control purge tenant={} idempotencyKeys={} volumeCounters={}",
                                        tenant, purged.getT1(), purged.getT2());
                            }
                        })
                        .then()
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                        .onErrorResume(e -> {
                            log.warn("Request control purge skipped tenant '{}': {}", tenant, e.getMessage());
                            return Mono.empty();
                        }))
                .then()
                .onErrorResume(e -> {
                    log.warn("Request control purge skipped: {}", e.getMessage());
                    return Mono.empty();
                });
    }
}
