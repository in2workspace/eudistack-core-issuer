package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import reactor.core.publisher.Mono;

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

}
