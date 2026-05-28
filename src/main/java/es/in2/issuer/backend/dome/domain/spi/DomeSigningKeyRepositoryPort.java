package es.in2.issuer.backend.dome.domain.spi;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeSigningKey;
import reactor.core.publisher.Mono;

public interface DomeSigningKeyRepositoryPort {

    Mono<DomeSigningKey> save(DomeSigningKey key);

    Mono<DomeSigningKey> findActiveByLegacyKeyId(String legacyKeyId);

    Mono<Void> deactivateByLegacyKeyId(String legacyKeyId);
}

