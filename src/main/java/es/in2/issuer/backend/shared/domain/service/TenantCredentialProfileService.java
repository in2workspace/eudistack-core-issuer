package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Resolves which credential profiles are available for the current tenant.
 * Reads from tenant_credential_profile table (via search_path).
 * If the table has no rows, all global profiles are returned (backward compat).
 */
public interface TenantCredentialProfileService {

    /**
     * Returns credential profiles filtered by what the current tenant has enabled.
     * If no tenant-specific config exists, returns all profiles.
     */
    Mono<Map<String, CredentialProfile>> getAvailableProfiles();

    /**
     * Returns the set of enabled credential_configuration_ids for the current tenant.
     * Empty set means all are allowed (backward compat).
     */
    Mono<Set<String>> getEnabledConfigurationIds();

    /**
     * Checks if a specific credential_configuration_id is allowed for the current tenant.
     */
    Mono<Boolean> isProfileAllowed(String credentialConfigurationId);

    /**
     * Returns the full global catalog, each entry flagged with whether it is enabled
     * for the current tenant. Empty tenant table ⇒ all entries enabled (backward compat).
     * Errors if the tenant cannot be resolved from the reactive context (admin path is
     * stricter than the read side, which tolerates a missing tenant).
     */
    Mono<List<CredentialCatalogEntryDto>> getCatalog();

    /**
     * Replaces the set of enabled credential_configuration_ids for the current tenant.
     * Validates {@code enabledConfigurationIds ⊆ registry} (unknown ids ⇒ error, no write),
     * performs an atomic transactional delete+insert, and invalidates the tenant cache
     * only after a successful commit. An empty set clears the config (empty = all).
     */
    Mono<Void> updateCatalog(Set<String> enabledConfigurationIds);

}
