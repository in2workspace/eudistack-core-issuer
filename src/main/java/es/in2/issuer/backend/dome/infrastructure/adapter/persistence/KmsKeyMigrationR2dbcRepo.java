package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.KmsKeyMigration;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

interface KmsKeyMigrationR2dbcRepo extends ReactiveCrudRepository<KmsKeyMigration, UUID> {

    @Query("SELECT * FROM kms_key_migration WHERE legacy_key_id = :legacyKeyId LIMIT 1")
    Mono<KmsKeyMigration> findByLegacyKeyId(String legacyKeyId);
}

