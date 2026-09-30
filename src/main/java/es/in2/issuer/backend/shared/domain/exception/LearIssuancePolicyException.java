package es.in2.issuer.backend.shared.domain.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Denial of the LEAR issuance policy ({@code RequireLearCredentialIssuanceRule}) carrying a stable,
 * machine-readable {@link Reason}. The HTTP layer exposes it as the {@code reason} member of the
 * error body so a client can explain the business rule to the operator instead of a generic
 * "forbidden" -- the free-text message stays for logs and is not a contract.
 */
@Getter
public class LearIssuancePolicyException extends InsufficientPermissionException {

    private final Reason reason;

    public LearIssuancePolicyException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    @Getter
    @RequiredArgsConstructor
    public enum Reason {
        OPERATOR_LACKS_ONBOARDING("operator_lacks_onboarding"),
        ONBOARDING_DELEGATION_REQUIRES_TENANT_ADMIN("onboarding_delegation_requires_tenant_admin"),
        ONBOARDING_DELEGATION_REQUIRES_MULTI_ORG("onboarding_delegation_requires_multi_org"),
        ONBOARDING_DELEGATION_SAME_ORG("onboarding_delegation_same_org"),
        CERTIFICATION_DELEGATION_REQUIRES_TENANT_ADMIN("certification_delegation_requires_tenant_admin"),
        CERTIFICATION_DELEGATION_REQUIRES_MULTI_ORG("certification_delegation_requires_multi_org"),
        MANDATOR_ORGANIZATION_MISSING("mandator_organization_missing"),
        ON_BEHALF_REQUIRES_TENANT_ADMIN("on_behalf_requires_tenant_admin"),
        ON_BEHALF_REQUIRES_MULTI_ORG("on_behalf_requires_multi_org");

        private final String code;
    }
}
