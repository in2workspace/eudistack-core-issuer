package es.in2.issuer.backend.shared.domain.model.dto;

import jakarta.validation.constraints.NotNull;

import java.util.Set;

/**
 * Write payload for {@code PUT /admin/v1/credential-catalog}. Replaces the full set
 * of credential configuration ids enabled for the current tenant.
 *
 * <p>An empty set is valid and explicitly clears the tenant config, which re-activates
 * the "empty = all enabled" invariant (see EC-01). A {@code null} set is rejected (400).
 */
public record UpdateCredentialCatalogRequest(
        @NotNull(message = "enabledConfigurationIds must not be null")
        Set<String> enabledConfigurationIds
) {}
