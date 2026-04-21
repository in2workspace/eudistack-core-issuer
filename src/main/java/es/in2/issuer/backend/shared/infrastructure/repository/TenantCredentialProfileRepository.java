package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

import java.util.UUID;

@Repository
public interface TenantCredentialProfileRepository extends ReactiveCrudRepository<TenantCredentialProfile, UUID> {

    Flux<TenantCredentialProfile> findAllByEnabledTrue();

}
