package es.in2.issuer.backend.shared.domain.model.dto;

import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

/**
 * Write payload for {@code PUT /admin/v1/credential-catalog}. Replaces the full set
 * of credential configuration ids enabled for the current tenant.
 *
 * <p>A {@code null} or empty set is rejected (400): an empty catalog now means
 * "nothing enabled" rather than the former "empty = all enabled" invariant, so it can
 * only be reached by mistake. A tenant that must stop issuing is handled by disabling
 * the tenant, not by emptying its catalog.
 */
public record UpdateCredentialCatalogRequest(
        @NotEmpty(message = "enabledConfigurationIds must not be empty")
        Set<String> enabledConfigurationIds
) {}
