package es.in2.issuer.backend.shared.domain.model.enums;

/**
 * Represents the authorization role of the current user within the tenant context.
 *
 * <ul>
 *   <li>{@code SYSADMIN} — Platform administrator. Has power
 *       {@code organization/EUDISTACK/System/Administration}. Equivalent to
 *       TenantAdmin when operating outside the {@code platform} tenant.</li>
 *   <li>{@code TENANT_ADMIN} — Administrator of a specific tenant.
 *       {@code organizationId == tenant.admin_organization_id} plus domain power.</li>
 *   <li>{@code LEAR} — Legal Entity Appointed Representative.
 *       Domain power but different organization than the tenant admin.</li>
 * </ul>
 */
public enum UserRole {
    SYSADMIN,
    TENANT_ADMIN,
    LEAR
}
