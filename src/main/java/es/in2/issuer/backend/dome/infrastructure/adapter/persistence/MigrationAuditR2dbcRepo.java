package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationAuditEntry;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.util.UUID;

interface MigrationAuditR2dbcRepo extends ReactiveCrudRepository<MigrationAuditEntry, UUID> {

    @Query("SELECT * FROM migration_audit WHERE source_record_id = :sourceRecordId AND outcome = :outcome LIMIT 1")
    Mono<MigrationAuditEntry> findBySourceRecordIdAndOutcome(UUID sourceRecordId, String outcome);
}
