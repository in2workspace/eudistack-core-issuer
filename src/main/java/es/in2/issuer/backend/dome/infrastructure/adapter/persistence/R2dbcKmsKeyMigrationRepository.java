package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.KmsKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Slf4j
@Repository
@RequiredArgsConstructor
public class R2dbcKmsKeyMigrationRepository implements KmsKeyMigrationRepositoryPort {

    private final KmsKeyMigrationR2dbcRepo springDataRepo;

    @Override
    public Mono<KmsKeyMigration> findByLegacyKeyId(LegacyKeyId keyId) {
        log.debug("Looking up KmsKeyMigration by legacyKeyId");
        return springDataRepo.findByLegacyKeyId(keyId.value());
    }

    @Override
    public Mono<KmsKeyMigration> save(KmsKeyMigration entity) {
        log.debug("Saving KmsKeyMigration entity, id={}", entity.getId());
        if (entity.getId() == null) {
            return springDataRepo.save(entity);
        }
        return springDataRepo.existsById(entity.getId())
                .flatMap(idExists -> {
                    if (idExists) {
                        return springDataRepo.save(entity);
                    }
                    return springDataRepo.findByLegacyKeyId(entity.getLegacyKeyId())
                            .flatMap(existing -> {
                                entity.setId(existing.getId());
                                return springDataRepo.save(entity);
                            })
                            .switchIfEmpty(Mono.defer(() -> {
                                entity.setId(null);
                                return springDataRepo.save(entity);
                            }));
                });
    }

    @Override
    public Mono<KmsKeyMigration> updateStatus(LegacyKeyId keyId, MigrationStatus newStatus) {
        log.debug("Updating migration status to {} for legacyKeyId", newStatus);
        return springDataRepo.findByLegacyKeyId(keyId.value())
                .switchIfEmpty(Mono.error(new IllegalArgumentException(
                        "No migration record found for legacyKeyId")))
                .flatMap(entity -> {
                    MigrationStatus current = MigrationStatus.valueOf(entity.getMigrationStatus());
                    if (!current.canTransitionTo(newStatus)) {
                        return Mono.error(new IllegalStateException(
                                "Invalid status transition from " + current + " to " + newStatus));
                    }
                    entity.setMigrationStatus(newStatus.name());
                    return springDataRepo.save(entity);
                });
    }
}
