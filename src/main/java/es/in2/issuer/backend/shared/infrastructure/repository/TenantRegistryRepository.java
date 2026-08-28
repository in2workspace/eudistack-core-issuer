package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.TenantRegistry;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

@Repository
public interface TenantRegistryRepository extends ReactiveCrudRepository<TenantRegistry, String> {

    Flux<TenantRegistry> findAllByStatus(String status);

}
