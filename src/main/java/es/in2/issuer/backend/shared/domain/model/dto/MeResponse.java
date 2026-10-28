package es.in2.issuer.backend.shared.domain.model.dto;

import es.in2.issuer.backend.shared.domain.model.enums.UserRole;

/**
 * Response of GET /api/v1/me. Exposes the authorization role of the caller
 * resolved against the current tenant, so the frontend can render UI without
 * knowing which powers make each role.
 *
 * @param organizationIdentifier the mandator's organization ID from the token
 * @param role                   the resolved role for the current tenant
 * @param readOnly               true when SysAdmin is operating from the platform tenant
 * @param tenant                 the tenant schema resolved from the X-Tenant header
 */
public record MeResponse(
        String organizationIdentifier,
        UserRole role,
        boolean readOnly,
        String tenant,
        String tenantType
) {}
