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
 * A tenant with no rows has nothing enabled: the catalog must be configured
 * explicitly before the tenant can issue.
 */
public interface TenantCredentialProfileService {

    /**
     * Returns credential profiles filtered by what the current tenant has enabled.
     * No tenant-specific config ⇒ empty map.
     */
    Mono<Map<String, CredentialProfile>> getAvailableProfiles();

    /**
     * Returns the set of enabled credential_configuration_ids for the current tenant.
     * Empty set means nothing is allowed.
     */
    Mono<Set<String>> getEnabledConfigurationIds();

    /**
     * Checks if a specific credential_configuration_id is allowed for the current tenant.
     * Always false while the tenant catalog is unconfigured.
     */
    Mono<Boolean> isProfileAllowed(String credentialConfigurationId);

    /**
     * Returns the full global catalog, each entry flagged with whether it is enabled
     * for the current tenant. Errors with
     * {@link es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException}
     * (404) when no entry is enabled — an unconfigured tenant, or one whose stored ids are
     * all unknown to the registry. Errors if the tenant cannot be resolved from the reactive
     * context (admin path is stricter than the read side, which tolerates a missing tenant).
     */
    Mono<List<CredentialCatalogEntryDto>> getCatalog();

    /**
     * Replaces the set of enabled credential_configuration_ids for the current tenant.
     * Validates {@code enabledConfigurationIds ⊆ registry} (unknown ids ⇒ error, no write),
     * performs an atomic transactional delete+insert, and invalidates the tenant cache
     * only after a successful commit.
     *
     * <p>An empty set wipes the tenant catalog, leaving nothing enabled. The admin API
     * rejects it upfront (see {@code UpdateCredentialCatalogRequest}); it stays available
     * here as the reset primitive.
     */
    Mono<Void> updateCatalog(Set<String> enabledConfigurationIds);

}
