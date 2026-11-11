package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.LongStream;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;

/** Real Postgres coverage of the volume counters (EUD-269): atomic across concurrent requests and instances. */
class R2dbcVolumeCounterStoreIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    @Autowired
    private R2dbcVolumeCounterStore store;

    private <T> Mono<T> scoped(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private static Instant second(int offset) {
        return NOW.plusSeconds(offset);
    }

    private Mono<Map<Instant, Long>> increment(R2dbcVolumeCounterStore on, String key, int bucket) {
        return scoped(on.increment(key, second(bucket), second(bucket - 60)));
    }

    @Test
    void concurrentIncrements_fromTwoInstances_neverLoseACount() {
        String key = "issuance:" + UUID.randomUUID();
        R2dbcVolumeCounterStore otherInstance = new R2dbcVolumeCounterStore(databaseClient);

        List<Long> counts = Flux.range(0, 40)
                .flatMap(i -> increment(i % 2 == 0 ? store : otherInstance, key, 0)
                        .map(buckets -> buckets.get(second(0)))
                        .subscribeOn(Schedulers.parallel()))
                .collectList()
                .block();

        assertThat(counts).containsExactlyInAnyOrderElementsOf(LongStream.rangeClosed(1, 40).boxed().toList());
    }

    @Test
    void increment_readsTheBucketsOfTheWindow_andCountsApartPerKey() {
        String key = "read:" + UUID.randomUUID();
        increment(store, key, -70).block();
        increment(store, key, -30).block();
        increment(store, key, -30).block();

        StepVerifier.create(increment(store, key, 0))
                .expectNext(Map.of(second(-30), 2L, second(0), 1L))
                .verifyComplete();
        StepVerifier.create(increment(store, "read:" + UUID.randomUUID(), 0))
                .expectNext(Map.of(second(0), 1L))
                .verifyComplete();
    }

    @Test
    void purgeBefore_deletesOnlyTheBucketsOutOfTheWindow() {
        String key = "search:" + UUID.randomUUID();
        increment(store, key, -90).block();
        increment(store, key, -10).block();

        scoped(store.purgeBefore(second(-60))).block();

        // Read from a bucket whose window would still include -90 s if it had not been purged.
        StepVerifier.create(scoped(store.increment(key, second(0), second(-120))))
                .expectNext(Map.of(second(-10), 1L, second(0), 1L))
                .verifyComplete();
    }
}
