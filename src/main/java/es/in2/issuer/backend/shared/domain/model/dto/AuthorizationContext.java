package es.in2.issuer.backend.shared.domain.model.dto;

import es.in2.issuer.backend.shared.domain.model.enums.UserRole;

/**
 * Encapsulates the authorization context resolved from the access token.
 *
 * @param organizationIdentifier the mandator's organization ID from the token
 * @param role                   the resolved user role ({@link UserRole})
 * @param readOnly               true when the user is a SysAdmin operating from the
 *                               {@code platform} tenant (cross-tenant read-only view)
 */
public record AuthorizationContext(
        String organizationIdentifier,
        UserRole role,
        boolean readOnly
) {
    public boolean isSysAdmin() {
        return role == UserRole.SYSADMIN;
    }

    public boolean isTenantAdmin() {
        return role == UserRole.TENANT_ADMIN || isSysAdmin();
    }

    public boolean canWrite() {
        return !readOnly;
    }
}
