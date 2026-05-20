package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyCacheKey;
import es.in2.issuer.backend.dome.domain.model.sync.SyncCredentialsResult;
import reactor.core.publisher.Mono;
import java.util.Optional;

/**
 * Port to manage the idempotency cache for credential synchronization.
 */
public interface IdempotencyCachePort {

    /**
     * Retrieves the cached result for a given idempotency key.
     *
     * @param key   the compound idempotency cache key.
     * @return a Mono emitting an Optional containing the result if found
     */
    Mono<Optional<SyncCredentialsResult>> get(IdempotencyCacheKey key);

    /**
     * Stores a synchronization result in the cache
     *
     * @param key       the compound idempotency cache key
     * @param result    the result to cache.
     * @return an empty Mono signaling completion
     */
    Mono<Void> put(IdempotencyCacheKey key, SyncCredentialsResult result);

}
