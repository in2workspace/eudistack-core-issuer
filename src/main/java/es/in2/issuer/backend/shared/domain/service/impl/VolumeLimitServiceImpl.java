package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.RequestControlSecrets;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.RequesterKind;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.SlidingWindow;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitDecision;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitPolicy;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.VolumeLimitService;
import es.in2.issuer.backend.shared.domain.spi.VolumeCounterStore;
import es.in2.issuer.backend.shared.domain.util.LogSafe;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Counts each request in the shared counters and decides it against the limit of its operation:
 * the default of the policy, or, for the systems of an organization, the one support set for it in
 * the tenant configuration ({@value #ORGANIZATION_LIMIT_PREFIX}{@code <operation>.<organization>}),
 * which takes effect without a redeploy once the configuration cache refreshes: within a minute when the
 * organization had no limit of its own, within five minutes when it changes one it had (the cache of
 * {@link TenantConfigService}).
 *
 * <p>A rejected request is taken back from the counter, so a client that keeps retrying while it is over the
 * limit does not stay locked out: the limit counts the requests served in the last minute.
 *
 * <p>Once a counter is over its limit, each instance remembers it until its {@code Retry-After} and rejects
 * the requests of that counter without touching the database: a requester with a valid token, which has no
 * limit per address, cannot turn each of its rejections into two writes in the PostgreSQL every tenant shares.
 * No request would fit before then anyway: {@code Retry-After} is when the next one fits.
 */
@Slf4j
@Service
public class VolumeLimitServiceImpl implements VolumeLimitService {

    /** Tenant configuration key of the limit of the systems of one organization, before {@code <operation>.<organization>}. */
    public static final String ORGANIZATION_LIMIT_PREFIX = "issuer.volume_limit.";

    /**
     * How long the absence of a configured limit is remembered: most organizations have none, and without
     * remembering it every request of a system would read the configuration. A configured value is cached by
     * {@link TenantConfigService} itself.
     */
    static final Duration ORGANIZATION_LIMIT_CACHE_TTL = Duration.ofMinutes(1);

    /** Counters over their limit known to this instance, at most for one window. */
    static final int MAX_REMEMBERED_REJECTIONS = 50_000;

    private final VolumeLimitPolicy policy;
    private final VolumeCounterStore counterStore;
    private final TenantConfigService tenantConfigService;
    private final RequestControlSecrets secrets;
    private final Clock clock;
    private final Cache<String, Boolean> organizationsWithoutLimit = Caffeine.newBuilder()
            .expireAfterWrite(ORGANIZATION_LIMIT_CACHE_TTL)
            .maximumSize(10_000)
            .build();
    /** The counters over their limit, until their {@code Retry-After}. Never longer than a window. */
    private final Cache<String, Rejection> rejected;

    private record Rejection(int limit, Instant fitsAgainAt) { }

    public VolumeLimitServiceImpl(VolumeLimitPolicy policy, VolumeCounterStore counterStore,
                                  TenantConfigService tenantConfigService, RequestControlSecrets secrets, Clock clock) {
        this.policy = policy;
        this.counterStore = counterStore;
        this.tenantConfigService = tenantConfigService;
        this.secrets = secrets;
        this.clock = clock;
        this.rejected = Caffeine.newBuilder()
                .expireAfterWrite(policy.window().length())
                .maximumSize(MAX_REMEMBERED_REJECTIONS)
                .build();
    }

    @Override
    public Mono<VolumeLimitDecision> check(ApiOperation operation, Requester requester) {
        return Mono.defer(() -> {
            Instant now = clock.instant();
            SlidingWindow window = policy.window();
            String counterKey = counterKey(secrets, operation, requester);
            VolumeLimitDecision remembered = rememberedRejection(counterKey, now);
            if (remembered != null) {
                return Mono.just(remembered);
            }
            Instant bucket = window.currentBucket(now);
            return limitOf(operation, requester)
                    .flatMap(limit -> counterStore.increment(counterKey, bucket, window.oldestCountedBucket(now))
                            .map(buckets -> window.decide(buckets, limit, now)))
                    .flatMap(decision -> {
                        if (decision.allowed()) {
                            return Mono.just(decision);
                        }
                        rejected.put(counterKey,
                                new Rejection(decision.limit(), now.plusSeconds(decision.retryAfterSeconds())));
                        return counterStore.undo(counterKey, bucket).thenReturn(decision);
                    });
        });
    }

    /**
     * The rejection this instance remembers for the counter, with the seconds left until its {@code Retry-After}
     * (rounded up); {@code null} when there is none or it has passed.
     */
    private VolumeLimitDecision rememberedRejection(String counterKey, Instant now) {
        Rejection remembered = rejected.getIfPresent(counterKey);
        if (remembered == null) {
            return null;
        }
        if (!remembered.fitsAgainAt().isAfter(now)) {
            rejected.invalidate(counterKey);
            return null;
        }
        long millisLeft = Duration.between(now, remembered.fitsAgainAt()).toMillis();
        return VolumeLimitDecision.rejected(remembered.limit(), Math.max(1, (millisLeft + 999) / 1000));
    }

    private Mono<Integer> limitOf(ApiOperation operation, Requester requester) {
        int defaultLimit = policy.of(operation).of(requester.kind());
        if (requester.kind() != RequesterKind.SYSTEM) {
            return Mono.just(defaultLimit);
        }
        String key = ORGANIZATION_LIMIT_PREFIX + operation.key() + "." + requester.organizationIdentifier();
        return Mono.deferContextual(ctx -> {
            String cacheKey = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "") + ":" + key;
            if (organizationsWithoutLimit.getIfPresent(cacheKey) != null) {
                return Mono.just(defaultLimit);
            }
            return tenantConfigService.getString(key)
                    .map(value -> Optional.ofNullable(parseLimit(key, value)))
                    .defaultIfEmpty(Optional.empty())
                    .doOnNext(found -> {
                        if (found.isEmpty()) {
                            organizationsWithoutLimit.put(cacheKey, Boolean.TRUE);
                        }
                    })
                    .map(found -> found.orElse(defaultLimit));
        })
                // A broken configuration store must not take the API down: the default still protects it.
                .onErrorResume(e -> {
                    log.warn("Volume limit configuration '{}' unreadable, using the default: {}", LogSafe.of(key),
                            e.toString());
                    return Mono.just(defaultLimit);
                });
    }

    private static Integer parseLimit(String key, String value) {
        try {
            int limit = Integer.parseInt(value.trim());
            if (limit >= 1) {
                return limit;
            }
        } catch (NumberFormatException _) {
            // logged below
        }
        log.warn("Volume limit configuration '{}' is not a positive integer, using the default", LogSafe.of(key));
        return null;
    }

    /**
     * The operation in clear (for support), the requester only as an HMAC with the request-control secret: it
     * may name a person, and the database alone does not allow testing guessed requesters.
     */
    static String counterKey(RequestControlSecrets secrets, ApiOperation operation, Requester requester) {
        return operation.key() + ":"
                + secrets.current().mac(RequestControlSecrets.VOLUME_COUNTER_KEY, requester.countingScope());
    }
}
