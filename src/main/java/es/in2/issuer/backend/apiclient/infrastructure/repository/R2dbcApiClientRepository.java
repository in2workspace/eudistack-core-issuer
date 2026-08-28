package es.in2.issuer.backend.apiclient.infrastructure.repository;

import es.in2.issuer.backend.apiclient.infrastructure.persistence.ApiClientEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface R2dbcApiClientRepository extends ReactiveCrudRepository<ApiClientEntity, UUID> {

    /**
     * The table lives in the tenant schema, resolved by search_path — no
     * tenant column, no tenant parameter.
     */
    Mono<ApiClientEntity> findByClientId(String clientId);
}
