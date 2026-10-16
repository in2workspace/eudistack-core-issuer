package es.in2.issuer.backend.shared.domain.model.enums;

/**
 * The user type of the current caller within the tenant, as the power-based authorization
 * recognizes it from the powers of its attestation alone (EUD-253, prd.md §2):
 *
 * <ul>
 *   <li>{@code SYSADMIN} — Platform administrator, {@code organization · EUDISTACK · System · Administration}.
 *       Acts as the administrator of the tenant it is in; read-only from the {@code platform} tenant.</li>
 *   <li>{@code TENANT_ADMIN} — Administrator of the tenant, {@code organization · <tenant> · Onboarding · Execute}.</li>
 *   <li>{@code LEAR} — Administrator of the organization its attestation represents,
 *       {@code domain · <tenant> · Onboarding · Execute}.</li>
 *   <li>{@code USER} — An attestation of the tenant without any of those powers: no issuer action.</li>
 * </ul>
 */
public enum UserRole {
    SYSADMIN,
    TENANT_ADMIN,
    LEAR,
    USER;

    /** Maps a user type id of the authorization matrix to the role exposed to clients. */
    public static UserRole fromUserType(String userType) {
        return switch (userType) {
            case "platform_admin" -> SYSADMIN;
            case "tenant_admin" -> TENANT_ADMIN;
            case "organization_admin" -> LEAR;
            default -> USER;
        };
    }
}
