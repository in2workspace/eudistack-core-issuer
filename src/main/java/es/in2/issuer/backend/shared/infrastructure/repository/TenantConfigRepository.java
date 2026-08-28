package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.TenantConfig;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface TenantConfigRepository extends ReactiveCrudRepository<TenantConfig, UUID> {

    Mono<TenantConfig> findByConfigKey(String configKey);

}
