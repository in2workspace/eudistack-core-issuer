package es.in2.issuer.backend.shared.domain.model.dto;

/**
 * One entry of the tenant credential catalog: a globally-defined credential
 * configuration plus whether it is enabled for the current tenant.
 *
 * @param credentialConfigurationId id from {@code CredentialProfileRegistry}
 * @param displayName               human-readable name (first display entry, no i18n yet)
 * @param enabled                   true only if this id is explicitly enabled for the
 *                                  current tenant; a tenant with no stored config has
 *                                  every entry disabled
 */
public record CredentialCatalogEntryDto(
        String credentialConfigurationId,
        String displayName,
        boolean enabled
) {}
