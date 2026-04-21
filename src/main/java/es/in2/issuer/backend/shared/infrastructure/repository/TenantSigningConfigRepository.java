package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface TenantSigningConfigRepository extends ReactiveCrudRepository<TenantSigningConfig, UUID> {

    /**
     * Returns the first (and expected only) signing config for the current tenant.
     * The table lives in the tenant schema, resolved by search_path.
     */
    Mono<TenantSigningConfig> findFirstByOrderByCreatedAtDesc();

}
