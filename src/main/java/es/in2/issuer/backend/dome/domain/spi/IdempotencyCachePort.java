package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyCacheKey;
import es.in2.issuer.backend.dome.domain.model.sync.SyncCredentialsResult;
import reactor.core.publisher.Mono;
import java.util.Optional;

/**
 * Outgoing port to manage the idempotency cache for credential synchronization.
 * Defines the contract for storing and retrieving caching data without tying the domain
 * to a specific database technology.
 */
public interface IdempotencyCachePort {

    Mono<Optional<SyncCredentialsResult>> get(IdempotencyCacheKey key);

    Mono<Void> put(IdempotencyCacheKey key, SyncCredentialsResult result);

}
