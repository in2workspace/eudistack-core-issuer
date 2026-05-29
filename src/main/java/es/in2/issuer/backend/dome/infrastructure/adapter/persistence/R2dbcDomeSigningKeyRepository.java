package es.in2.issuer.backend.dome.infrastructure.adapter.persistence;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeSigningKey;
import es.in2.issuer.backend.dome.domain.spi.DomeSigningKeyRepositoryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
@RequiredArgsConstructor
@Slf4j
public class R2dbcDomeSigningKeyRepository implements DomeSigningKeyRepositoryPort {

    private final DomeSigningKeyR2dbcRepo repo;

    @Override
    public Mono<DomeSigningKey> save(DomeSigningKey key) {
        log.debug("Saving DomeSigningKey keyId={}, holderId={}", key.getKeyId(), key.getHolderId());
        return repo.insertKey(
                key.getKeyId(),
                key.getHolderId(),
                key.getCredentialId(),
                key.getTenantId(),
                key.getPrivateKey(),
                key.getPublicJwk(),
                key.getAlgorithm(),
                key.getFormat(),
                key.getCreatedAt());
    }

    @Override
    public Mono<DomeSigningKey> findActiveByLegacyKeyId(String legacyKeyId) {
        return repo.findActiveByLegacyKeyId(legacyKeyId);
    }

    @Override
    public Mono<Void> deactivateByLegacyKeyId(String legacyKeyId) {
        return repo.deactivateByLegacyKeyId(legacyKeyId);
    }
}
