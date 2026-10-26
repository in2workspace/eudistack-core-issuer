package es.in2.issuer.backend.shared.domain.service;

import reactor.core.publisher.Mono;

import java.util.List;

public interface TenantRegistryService {

    Mono<List<String>> getActiveTenantSchemas();

    /**
     * Returns the tenant_type for the given schema
     * ({@code simple}, {@code multi_org}, {@code platform}), or empty Mono
     * if the tenant is not found.
     */
    Mono<String> getTenantType(String schemaName);

    /**
     * Returns the human-readable display name of the tenant, or the schema name itself when the
     * tenant is unknown or has no display name.
     */
    Mono<String> getDisplayName(String schemaName);

}
