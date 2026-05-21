package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.keymigration.KmsKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import reactor.core.publisher.Mono;

public interface KmsKeyMigrationRepositoryPort {

    Mono<KmsKeyMigration> findByLegacyKeyId(LegacyKeyId keyId);

    Mono<KmsKeyMigration> save(KmsKeyMigration entity);

    Mono<KmsKeyMigration> updateStatus(LegacyKeyId keyId, MigrationStatus newStatus);
}

