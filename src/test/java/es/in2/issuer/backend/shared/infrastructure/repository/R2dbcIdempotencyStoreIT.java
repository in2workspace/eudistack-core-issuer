package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Real Postgres coverage of the idempotency store (EUD-269): the atomic claim across concurrent requests, the
 * replay by another store instance (another issuer instance, or the same one after a restart), the lease
 * takeover and the release of failed requests.
 */
class R2dbcIdempotencyStoreIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";
    private static final Duration LEASE = Duration.ofMinutes(2);
    private static final Duration RETENTION = Duration.ofHours(24);

    @Autowired
    private R2dbcIdempotencyStore store;

    private <T> Mono<T> scoped(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private static String scope() {
        return UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
    }

    private static String owner() {
        return UUID.randomUUID().toString();
    }

    private Mono<IdempotencyClaim> claim(R2dbcIdempotencyStore on, String scope, String hash, Instant now) {
        return scoped(on.claim(scope, hash, owner(), now, now.plus(LEASE), now.plus(RETENTION)));
    }

    private static StoredResponse response() {
        return new StoredResponse(200, "application/json", "/api/v1/issuances/42",
                "{\"responses\":[]}".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void sameKeyAndBody_afterCompleting_isReplayed_alsoByAnotherInstance() {
        String scope = scope();
        Instant now = Instant.now();
        IdempotencyClaim first = claim(store, scope, "h1", now).block();
        assertThat(first).isInstanceOf(IdempotencyClaim.Acquired.class);
        IdempotencyClaim.Acquired acquired = (IdempotencyClaim.Acquired) first;
        scoped(store.complete(scope, acquired.ownerId(), response())).block();

        // Another adapter on the same database: another instance, or this one after a restart.
        R2dbcIdempotencyStore otherInstance = new R2dbcIdempotencyStore(databaseClient);
        StepVerifier.create(claim(otherInstance, scope, "h1", now.plusSeconds(5)))
                .assertNext(claim -> assertThat(claim).isEqualTo(new IdempotencyClaim.Replay(response())))
                .verifyComplete();
    }

    @Test
    void sameKeyOtherBody_isKeyReused_whetherCompletedOrInProgress() {
        String inProgress = scope();
        String completed = scope();
        Instant now = Instant.now();
        claim(store, inProgress, "h1", now).block();
        IdempotencyClaim.Acquired done = (IdempotencyClaim.Acquired) claim(store, completed, "h1", now).block();
        scoped(store.complete(completed, done.ownerId(), response())).block();

        StepVerifier.create(claim(store, inProgress, "h2", now)).expectNext(new IdempotencyClaim.KeyReused()).verifyComplete();
        StepVerifier.create(claim(store, completed, "h2", now)).expectNext(new IdempotencyClaim.KeyReused()).verifyComplete();
    }

    @Test
    void concurrentRequestsWithTheSameKey_onlyOneIsProcessed() {
        String scope = scope();
        Instant now = Instant.now();

        List<IdempotencyClaim> claims = Flux.range(0, 8)
                .flatMap(i -> claim(store, scope, "h1", now).subscribeOn(Schedulers.parallel()))
                .collectList()
                .block();

        assertThat(claims).hasSize(8);
        assertThat(claims).filteredOn(IdempotencyClaim.Acquired.class::isInstance).hasSize(1);
        assertThat(claims).filteredOn(IdempotencyClaim.InProgress.class::isInstance).hasSize(7);
    }

    @Test
    void aFailedRequest_releasesTheKey_soARetryIsProcessedAgain() {
        String scope = scope();
        Instant now = Instant.now();
        IdempotencyClaim.Acquired acquired = (IdempotencyClaim.Acquired) claim(store, scope, "h1", now).block();

        scoped(store.release(scope, acquired.ownerId())).block();

        StepVerifier.create(claim(store, scope, "h1", now))
                .assertNext(claim -> assertThat(claim).isInstanceOf(IdempotencyClaim.Acquired.class))
                .verifyComplete();
    }

    @Test
    void aRenewedLease_isNotTakenOver_untilItEndsAgain() {
        String scope = scope();
        Instant now = Instant.now();
        IdempotencyClaim.Acquired running = (IdempotencyClaim.Acquired) claim(store, scope, "h1", now).block();
        Instant afterFirstLease = now.plus(LEASE).plusSeconds(1);

        scoped(store.renew(scope, running.ownerId(), afterFirstLease.plus(LEASE))).block();

        StepVerifier.create(claim(store, scope, "h1", afterFirstLease))
                .expectNext(new IdempotencyClaim.InProgress()).verifyComplete();
        assertThat(claim(store, scope, "h1", afterFirstLease.plus(LEASE).plusSeconds(1)).block())
                .isInstanceOf(IdempotencyClaim.Acquired.class);
    }

    @Test
    void anAbandonedRequest_whoseLeaseEnded_canBeTakenOverWithTheSameBodyOnly() {
        String scope = scope();
        Instant now = Instant.now();
        IdempotencyClaim.Acquired abandoned = (IdempotencyClaim.Acquired) claim(store, scope, "h1", now).block();
        Instant afterLease = now.plus(LEASE).plusSeconds(1);

        StepVerifier.create(claim(store, scope, "h2", afterLease)).expectNext(new IdempotencyClaim.KeyReused()).verifyComplete();
        IdempotencyClaim takeover = claim(store, scope, "h1", afterLease).block();
        assertThat(takeover).isInstanceOf(IdempotencyClaim.Acquired.class);

        // The abandoned request no longer holds the key: it can neither store its response nor free the key.
        scoped(store.complete(scope, abandoned.ownerId(), response())).block();
        scoped(store.release(scope, abandoned.ownerId())).block();
        StepVerifier.create(claim(store, scope, "h1", afterLease)).expectNext(new IdempotencyClaim.InProgress()).verifyComplete();
    }

    @Test
    void afterTheRetention_theKeyIsNew_andThePurgeDeletesIt() {
        String scope = scope();
        Instant now = Instant.now().minus(25, ChronoUnit.HOURS);
        IdempotencyClaim.Acquired old = (IdempotencyClaim.Acquired) claim(store, scope, "h1", now).block();
        scoped(store.complete(scope, old.ownerId(), response())).block();

        StepVerifier.create(scoped(store.purgeExpired(Instant.now())))
                .assertNext(purged -> assertThat(purged).isPositive())
                .verifyComplete();
        StepVerifier.create(claim(store, scope, "h2", Instant.now()))
                .assertNext(claim -> assertThat(claim).isInstanceOf(IdempotencyClaim.Acquired.class))
                .verifyComplete();
    }

    @Test
    void anExpiredKeyThatWasNotPurged_isAlsoNew() {
        String scope = scope();
        Instant now = Instant.now().minus(25, ChronoUnit.HOURS);
        IdempotencyClaim.Acquired old = (IdempotencyClaim.Acquired) claim(store, scope, "h1", now).block();
        scoped(store.complete(scope, old.ownerId(), response())).block();

        StepVerifier.create(claim(store, scope, "h2", Instant.now()))
                .assertNext(claim -> assertThat(claim).isInstanceOf(IdempotencyClaim.Acquired.class))
                .verifyComplete();
    }
}
