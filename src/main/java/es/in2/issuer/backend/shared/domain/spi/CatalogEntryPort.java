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
}
