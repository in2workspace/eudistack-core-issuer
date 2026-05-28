package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.DomeKeyMigrationRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
@RequiredArgsConstructor
@Slf4j
public class R2dbcDomeKeyMigrationRepository implements DomeKeyMigrationRepositoryPort {

    private final DomeKeyMigrationR2dbcRepo repo;

    @Override
    public Mono<DomeKeyMigration> findByLegacyKeyId(LegacyKeyId keyId) {
        return repo.findByLegacyKeyId(keyId.value());
    }

    @Override
    public Mono<DomeKeyMigration> save(DomeKeyMigration entity) {
        if (entity.getId() == null) {
            return repo.save(entity);
        }
        return repo.existsById(entity.getId())
                .flatMap(exists -> {
                    if (Boolean.TRUE.equals(exists)) {
                        return repo.save(entity);
                    }
                    return repo.findByLegacyKeyId(entity.getLegacyKeyId())
                            .flatMap(existing -> {
                                entity.setId(existing.getId());
                                return repo.save(entity);
                            })
                            .switchIfEmpty(repo.save(entity));
                });
    }

    @Override
    public Mono<DomeKeyMigration> updateStatus(LegacyKeyId keyId, MigrationStatus status) {
        return repo.findByLegacyKeyId(keyId.value())
                .switchIfEmpty(Mono.error(new IllegalStateException(
                        "No DomeKeyMigration found for legacyKeyId: " + keyId.value())))
                .flatMap(entity -> {
                    MigrationStatus current = MigrationStatus.valueOf(entity.getMigrationStatus());
                    if (!current.canTransitionTo(status)) {
                        return Mono.error(new IllegalStateException(
                                "Invalid transition from " + current + " to " + status
                                        + " for legacyKeyId: " + keyId.value()));
                    }
                    entity.setMigrationStatus(status.name());
                    return repo.save(entity);
                });
    }
}

