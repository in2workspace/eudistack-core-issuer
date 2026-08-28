package es.in2.issuer.backend.apiclient.infrastructure.repository;

import es.in2.issuer.backend.apiclient.domain.model.ApiClient;
import es.in2.issuer.backend.apiclient.domain.spi.ApiClientRepository;
import es.in2.issuer.backend.apiclient.infrastructure.persistence.ApiClientEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class ApiClientRepositoryAdapter implements ApiClientRepository {

    private final R2dbcApiClientRepository r2dbcApiClientRepository;

    @Override
    public Mono<ApiClient> findByClientId(String clientId) {
        return r2dbcApiClientRepository.findByClientId(clientId).map(this::toDomain);
    }

    private ApiClient toDomain(ApiClientEntity entity) {
        return new ApiClient(
                entity.clientId(),
                entity.authorizationStatus(),
                entity.canTriggerIssuance(),
                entity.secretHash()
        );
    }
}
