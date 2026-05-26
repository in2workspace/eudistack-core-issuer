package es.in2.issuer.backend.dome.application.service;

import es.in2.issuer.backend.dome.domain.model.keymigration.KmsKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;


@Slf4j
@Service
@RequiredArgsConstructor
public class KeyMigrationStateService {

    private final KmsKeyMigrationRepositoryPort migrationRepo;

    public Mono<KmsKeyMigration> transitionTo(LegacyKeyId keyId, MigrationStatus target) {
        log.debug("transitionTo: keyId={} target={}", keyId.value(), target);
        return migrationRepo.findByLegacyKeyId(keyId)
                .switchIfEmpty(Mono.defer(() -> {
                    log.debug("No migration record found for keyId={}, creating PENDING entry", keyId.value());
                    KmsKeyMigration newRow = KmsKeyMigration.builder()
                            .legacyKeyId(keyId.value())
                            .migrationStatus(MigrationStatus.PENDING.name())
                            .build();
                    return migrationRepo.save(newRow);
                }))
                .flatMap(entity -> {
                    MigrationStatus current = MigrationStatus.valueOf(entity.getMigrationStatus());
                    if (current == target) {
                        log.debug("transitionTo: already in target state, no-op for keyId={} status={}", keyId.value(), target);
                        return Mono.just(entity);
                    }
                    if (!current.canTransitionTo(target)) {
                        return Mono.error(new IllegalStateException(
                                "Invalid transition: " + current + " → " + target));
                    }
                    entity.setMigrationStatus(target.name());
                    return migrationRepo.save(entity);
                });
    }

    public Mono<MigrationStatus> currentStatus(String legacyKeyId) {
        log.debug("currentStatus: legacyKeyId={}", legacyKeyId);
        return migrationRepo.findByLegacyKeyId(new LegacyKeyId(legacyKeyId))
                .map(entity -> MigrationStatus.valueOf(entity.getMigrationStatus()));
    }
}

