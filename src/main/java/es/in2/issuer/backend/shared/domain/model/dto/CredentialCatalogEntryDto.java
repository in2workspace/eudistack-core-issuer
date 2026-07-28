package es.in2.issuer.backend.shared.domain.model.dto;

/**
 * One entry of the tenant credential catalog: a globally-defined credential
 * configuration plus whether it is enabled for the current tenant.
 *
 * @param credentialConfigurationId id from {@code CredentialProfileRegistry}
 * @param displayName               human-readable name (first display entry, no i18n yet)
 * @param enabled                   true if enabled for the current tenant (or if the
 *                                  tenant has no explicit config — empty = all)
 */
public record CredentialCatalogEntryDto(
        String credentialConfigurationId,
        String displayName,
        boolean enabled
) {}
