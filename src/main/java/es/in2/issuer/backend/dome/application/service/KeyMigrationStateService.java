package es.in2.issuer.backend.dome.application.service;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.DomeKeyMigrationRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class KeyMigrationStateService {

    private final DomeKeyMigrationRepositoryPort domeKeyMigrationRepositoryPort;

    public Mono<DomeKeyMigration> transitionTo(LegacyKeyId keyId, MigrationStatus target) {
        return domeKeyMigrationRepositoryPort.findByLegacyKeyId(keyId)
                .switchIfEmpty(Mono.defer(() -> {
                    DomeKeyMigration newEntity = DomeKeyMigration.builder()
                            .legacyKeyId(keyId.value())
                            .migrationStatus(MigrationStatus.PENDING.name())
                            .build();
                    return domeKeyMigrationRepositoryPort.save(newEntity);
                }))
                .flatMap(entity -> {
                    MigrationStatus current = MigrationStatus.valueOf(entity.getMigrationStatus());
                    if (current == target) {
                        return Mono.just(entity);
                    }
                    if (!current.canTransitionTo(target)) {
                        return Mono.error(new IllegalStateException(
                                "Invalid transition from " + current + " to " + target
                                        + " for legacyKeyId: " + keyId.value()));
                    }
                    entity.setMigrationStatus(target.name());
                    return domeKeyMigrationRepositoryPort.save(entity);
                });
    }

    public Mono<MigrationStatus> currentStatus(String legacyKeyId) {
        return domeKeyMigrationRepositoryPort.findByLegacyKeyId(new LegacyKeyId(legacyKeyId))
                .map(entity -> MigrationStatus.valueOf(entity.getMigrationStatus()));
    }
}
