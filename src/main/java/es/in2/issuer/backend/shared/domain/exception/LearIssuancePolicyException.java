package es.in2.issuer.backend.shared.domain.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Denial of an issuer action by the power-based authorization ({@code PowerAuthorizationService},
 * EUD-253) carrying a stable, machine-readable {@link Reason}. The HTTP layer exposes it as the
 * {@code reason} member of the error body so a client can explain the business rule to the operator
 * instead of a generic "forbidden" -- the free-text message stays for logs and is not a contract.
 * The name is kept from when it only covered LEAR issuance: the wire contract did not change.
 */
@Getter
public class LearIssuancePolicyException extends InsufficientPermissionException {

    private final Reason reason;

    public LearIssuancePolicyException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    /**
     * Wire contract: the codes are duplicated in eudistack-mfe-credential-manager
     * ({@code LEAR_ISSUANCE_POLICY_REASONS} in {@code issuance-error.helpers.ts}), which maps each one
     * to an explanation. A code missing there degrades safely to the generic error message, but
     * nothing warns about it -- add, rename or remove codes in both places (and their i18n keys).
     * {@code LearIssuancePolicyExceptionTest} pins this list so a change here is a conscious one.
     */
    @Getter
    @RequiredArgsConstructor
    public enum Reason {
        /** The caller holds no power that allows the action in this tenant (user without powers). */
        OPERATOR_LACKS_ONBOARDING("operator_lacks_onboarding"),
        /** E3: only a tenant administrator grants the power to administer an organization. */
        ONBOARDING_DELEGATION_REQUIRES_TENANT_ADMIN("onboarding_delegation_requires_tenant_admin"),
        /** E5: only a tenant administrator grants the power to certify. */
        CERTIFICATION_DELEGATION_REQUIRES_TENANT_ADMIN("certification_delegation_requires_tenant_admin"),
        /** E4: only the platform administrator grants the power to administer the tenant. */
        TENANT_ADMIN_DELEGATION_REQUIRES_PLATFORM_ADMIN("tenant_admin_delegation_requires_platform_admin"),
        /** E9: a power outside the tenant's domain is only granted by the platform administrator. */
        FOREIGN_DOMAIN_DELEGATION_REQUIRES_PLATFORM_ADMIN("foreign_domain_delegation_requires_platform_admin"),
        /** E2: only a tenant administrator issues for another organization of the tenant. */
        ON_BEHALF_REQUIRES_TENANT_ADMIN("on_behalf_requires_tenant_admin"),
        /** E6: a product certification needs {@code domain · <tenant> · Certification · Attest}. */
        CERTIFICATION_POWER_REQUIRED("certification_power_required"),
        /** The platform administrator in the platform tenant can only read. */
        PLATFORM_TENANT_READ_ONLY("platform_tenant_read_only"),
        /** No rule for the action: denied by default (FR-11). */
        AUTHORIZATION_RULE_MISSING("authorization_rule_missing"),
        /** FR-07: the attestation type is not enabled in the tenant. */
        CREDENTIAL_TYPE_NOT_ENABLED("credential_type_not_enabled");

        private final String code;
    }
}
