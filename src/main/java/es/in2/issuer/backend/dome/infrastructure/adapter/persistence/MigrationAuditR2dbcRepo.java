package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationAuditEntry;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

interface MigrationAuditR2dbcRepo extends ReactiveCrudRepository<MigrationAuditEntry, UUID> {

    Mono<MigrationAuditEntry> findBySourceRecordId(UUID sourceRecordId);
}

