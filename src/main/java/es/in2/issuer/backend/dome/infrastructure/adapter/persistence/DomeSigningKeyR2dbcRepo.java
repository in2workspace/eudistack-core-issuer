package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeSigningKey;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

interface DomeSigningKeyR2dbcRepo extends ReactiveCrudRepository<DomeSigningKey, UUID> {

    @Query("SELECT * FROM dome_signing_key WHERE legacy_key_id = :legacyKeyId AND active = true LIMIT 1")
    Mono<DomeSigningKey> findActiveByLegacyKeyId(String legacyKeyId);

    @Query("UPDATE dome_signing_key SET active = false WHERE legacy_key_id = :legacyKeyId")
    Mono<Void> deactivateByLegacyKeyId(String legacyKeyId);
}

