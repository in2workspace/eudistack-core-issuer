package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface TenantSigningConfigRepository extends ReactiveCrudRepository<TenantSigningConfig, UUID> {

    /**
     * Returns the newest signing config of the current tenant with the given status; the active
     * one is {@code "active"} (at most one per tenant schema). The table lives in the tenant
     * schema, resolved by search_path.
     */
    Mono<TenantSigningConfig> findFirstByStatusOrderByCreatedAtDesc(String status);

}
