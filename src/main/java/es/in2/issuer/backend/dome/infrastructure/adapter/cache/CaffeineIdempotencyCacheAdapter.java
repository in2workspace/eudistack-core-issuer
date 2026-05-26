package es.in2.issuer.backend.dome.infrastructure.adapter.cache;

import com.github.benmanes.caffeine.cache.Cache;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyCacheKey;
import es.in2.issuer.backend.dome.domain.model.sync.SyncCredentialsResult;
import es.in2.issuer.backend.dome.domain.spi.IdempotencyCachePort;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Caffeine-based implementation of the IdempotencyCachePort.
 * Wraps synchronous cache operations into reactive Mono types.
 */
@Component
public class CaffeineIdempotencyCacheAdapter implements IdempotencyCachePort {

    private final Cache<IdempotencyCacheKey, SyncCredentialsResult> cache;

    public CaffeineIdempotencyCacheAdapter(Cache<IdempotencyCacheKey, SyncCredentialsResult> cache) {
        this.cache = cache;
    }

    @Override
    public Mono<Optional<SyncCredentialsResult>> get(IdempotencyCacheKey key) {
        return Mono.fromCallable(() -> Optional.ofNullable(cache.getIfPresent(key)));
    }

    @Override
    public Mono<Void> put(IdempotencyCacheKey key, SyncCredentialsResult result) {
        return Mono.fromRunnable(() -> cache.put(key, result));
    }
}