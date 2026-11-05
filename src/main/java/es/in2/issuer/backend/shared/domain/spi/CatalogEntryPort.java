package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Persistence port for the tenant's {@link CatalogEntry} rows (EUD-266). Tenant-scoped through the
 * Reactor context like every other repository. {@code CatalogEntryR2dbcAdapter} (infrastructure) is
 * the sole implementation.
 */
public interface CatalogEntryPort {

    Flux<CatalogEntry> findAll();

    Flux<CatalogEntry> findAllByEnabled(boolean enabled);

    Mono<CatalogEntry> findById(String credentialConfigurationId);

    /**
     * Inserts a new entry at version 0 and returns it as stored.
     *
     * @throws es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException
     *         if the {@code credential_configuration_id} or the {@code schema_uri} is already taken
     */
    Mono<CatalogEntry> insert(CatalogEntry entry);

    /**
     * Replaces the configuration of the entry stored under the same {@code credential_configuration_id}
     * only if its version is still {@code expectedVersion}, incrementing the version. The schema URI
     * is written only while the stored one is {@code null}. Empty when the entry does not exist or
     * has another version: the caller tells the two apart with {@link #findById}.
     */
    Mono<Optional<CatalogEntry>> updateIfVersion(CatalogEntry entry, long expectedVersion);

    /**
     * Stores the completion of an entry not configured yet (D13) from its credential type file, only if its
     * version is still {@code expectedVersion}, and <em>keeps</em> that version. The completion only stores
     * what every read already shows for the row, so it is not a change of the catalog: its {@code ETag}
     * stays valid, and a concurrent change of an administrator made with it does not turn into a 412
     * (W3 of the EUD-323 review). Empty when the entry does not exist or has another version.
     */
    Mono<Optional<CatalogEntry>> fillIfVersion(CatalogEntry filled, long expectedVersion);
}
