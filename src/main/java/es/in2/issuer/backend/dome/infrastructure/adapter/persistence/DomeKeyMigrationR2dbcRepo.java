package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeKeyMigration;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface DomeKeyMigrationR2dbcRepo extends ReactiveCrudRepository<DomeKeyMigration, UUID> {

    @Query("SELECT * FROM dome_key_migration WHERE legacy_key_id = :legacyKeyId LIMIT 1")
    Mono<DomeKeyMigration> findByLegacyKeyId(String legacyKeyId);
}

