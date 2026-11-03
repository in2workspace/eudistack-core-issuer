package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.infrastructure.persistence.TenantOwnKeyEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface TenantOwnKeyRepository extends ReactiveCrudRepository<TenantOwnKeyEntity, UUID> {

    /** The own-key block of a signing configuration of the current tenant (tenant schema via search_path). */
    Mono<TenantOwnKeyEntity> findBySigningConfigurationId(UUID signingConfigurationId);
}
