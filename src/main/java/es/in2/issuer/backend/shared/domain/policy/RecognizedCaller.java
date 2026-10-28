package es.in2.issuer.backend.shared.domain.policy;

/**
 * A {@link Caller} with its user type resolved in the request's tenant, from its powers alone (FR-03).
 *
 * @param userType       id of the matrix user type ({@code platform_admin}, {@code tenant_admin},
 *                       {@code organization_admin}, {@code user})
 * @param actsAs         user type it acts as inside the tenant (the platform administrator acts as
 *                       tenant administrator, FR-04); equal to {@code userType} otherwise
 * @param readOnly       true when it may only perform actions that do not write (the platform
 *                       administrator in the platform tenant)
 * @param securityAction true when its actions are security actions in the trace (FR-14)
 */
public record RecognizedCaller(
        Caller caller,
        String tenant,
        String userType,
        String actsAs,
        boolean readOnly,
        boolean securityAction
) {
    public static final String PLATFORM_ADMIN = "platform_admin";
    public static final String TENANT_ADMIN = "tenant_admin";
    public static final String ORGANIZATION_ADMIN = "organization_admin";
    public static final String USER = "user";

    public String organizationIdentifier() {
        return caller.organizationIdentifier();
    }

    /** True for the platform administrator in the platform tenant: the read-only view of every tenant. */
    public boolean crossTenantView() {
        return readOnly && PLATFORM_ADMIN.equals(userType);
    }
}
