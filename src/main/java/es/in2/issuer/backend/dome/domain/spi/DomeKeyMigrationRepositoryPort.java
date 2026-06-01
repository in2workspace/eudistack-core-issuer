package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import reactor.core.publisher.Mono;

public interface DomeKeyMigrationRepositoryPort {

    Mono<DomeKeyMigration> findByLegacyKeyId(LegacyKeyId keyId);

    Mono<DomeKeyMigration> save(DomeKeyMigration entity);
}

