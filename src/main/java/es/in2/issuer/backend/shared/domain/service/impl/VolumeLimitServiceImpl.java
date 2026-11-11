package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.RequesterKind;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.SlidingWindow;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitDecision;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitPolicy;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.VolumeLimitService;
import es.in2.issuer.backend.shared.domain.spi.VolumeCounterStore;
import es.in2.issuer.backend.shared.domain.util.Sha256;
import lombok.RequiredArgsConstructor;
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
 * which takes effect without a redeploy once the configuration cache refreshes.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class VolumeLimitServiceImpl implements VolumeLimitService {

    /** Tenant configuration key of the limit of the systems of one organization, before {@code <operation>.<organization>}. */
    public static final String ORGANIZATION_LIMIT_PREFIX = "issuer.volume_limit.";

    /**
     * How long a configured limit, or its absence, is reused: most organizations have none, and without
     * remembering that every request of a system would read the configuration.
     */
    static final Duration ORGANIZATION_LIMIT_CACHE_TTL = Duration.ofMinutes(1);

    private final VolumeLimitPolicy policy;
    private final VolumeCounterStore counterStore;
    private final TenantConfigService tenantConfigService;
    private final Clock clock;
    private final Cache<String, Optional<Integer>> organizationLimits = Caffeine.newBuilder()
            .expireAfterWrite(ORGANIZATION_LIMIT_CACHE_TTL)
            .maximumSize(10_000)
            .build();

    @Override
    public Mono<VolumeLimitDecision> check(ApiOperation operation, Requester requester) {
        return Mono.defer(() -> {
            Instant now = clock.instant();
            SlidingWindow window = policy.window();
            return limitOf(operation, requester)
                    .flatMap(limit -> counterStore.increment(counterKey(operation, requester),
                                    window.currentBucket(now), window.oldestCountedBucket(now))
                            .map(buckets -> window.decide(buckets, limit, now)));
        });
    }

    private Mono<Integer> limitOf(ApiOperation operation, Requester requester) {
        int defaultLimit = policy.of(operation).of(requester.kind());
        if (requester.kind() != RequesterKind.SYSTEM) {
            return Mono.just(defaultLimit);
        }
        String key = ORGANIZATION_LIMIT_PREFIX + operation.key() + "." + requester.organizationIdentifier();
        return Mono.deferContextual(ctx -> {
            String cacheKey = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "") + ":" + key;
            Optional<Integer> cached = organizationLimits.getIfPresent(cacheKey);
            Mono<Optional<Integer>> configured = cached != null
                    ? Mono.just(cached)
                    : tenantConfigService.getString(key)
                            .map(value -> Optional.ofNullable(parseLimit(key, value)))
                            .defaultIfEmpty(Optional.empty())
                            .doOnNext(found -> organizationLimits.put(cacheKey, found));
            return configured.map(found -> found.orElse(defaultLimit));
        })
                // A broken configuration store must not take the API down: the default still protects it.
                .onErrorResume(e -> {
                    log.warn("Volume limit configuration '{}' unreadable, using the default: {}", key, e.toString());
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
        log.warn("Volume limit configuration '{}' is not a positive integer, using the default", key);
        return null;
    }

    /** The operation in clear (for support), the requester only as a digest: it may name a person. */
    static String counterKey(ApiOperation operation, Requester requester) {
        return operation.key() + ":" + Sha256.hex(requester.countingScope());
    }
}
