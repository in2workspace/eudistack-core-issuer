package es.in2.issuer.backend.apiclient.domain.spi;

import es.in2.issuer.backend.apiclient.domain.model.ApiClient;
import reactor.core.publisher.Mono;

public interface ApiClientRepository {

    /**
     * Resolves an API client by its {@code client_id} within the tenant schema
     * bound to the current R2DBC connection (search_path). Never accepts a
     * tenant parameter from the caller — cross-tenant scoping is enforced by
     * the connection itself, not by application-level filtering.
     */
    Mono<ApiClient> findByClientId(String clientId);
}
