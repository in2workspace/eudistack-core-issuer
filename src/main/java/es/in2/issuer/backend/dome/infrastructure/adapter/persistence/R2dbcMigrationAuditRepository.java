package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationAuditEntry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@Repository
@RequiredArgsConstructor
public class R2dbcMigrationAuditRepository {

    private final MigrationAuditR2dbcRepo springDataRepo;

    public Mono<MigrationAuditEntry> save(MigrationAuditEntry entry) {
        log.debug("Saving MigrationAuditEntry, sourceRecordId={}", entry.getSourceRecordId());
        return springDataRepo.save(entry);
    }

    public Mono<MigrationAuditEntry> findBySourceRecordId(UUID sourceRecordId) {
        log.debug("Looking up MigrationAuditEntry by sourceRecordId={}", sourceRecordId);
        return springDataRepo.findBySourceRecordId(sourceRecordId);
    }
}

