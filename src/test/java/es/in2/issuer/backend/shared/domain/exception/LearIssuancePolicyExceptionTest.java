package es.in2.issuer.backend.shared.domain.exception;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class LearIssuancePolicyExceptionTest {

    /**
     * The reason codes are a wire contract duplicated in eudistack-mfe-credential-manager
     * ({@code LEAR_ISSUANCE_POLICY_REASONS} in {@code issuance-error.helpers.ts}). If this fails,
     * update that list and its i18n keys too, then this expectation.
     */
    @Test
    void reasonCodesMatchTheListTheCredentialManagerExplains() {
        assertThat(Arrays.stream(LearIssuancePolicyException.Reason.values()).map(LearIssuancePolicyException.Reason::getCode))
                .containsExactlyInAnyOrder(
                        "operator_lacks_onboarding",
                        "onboarding_delegation_requires_tenant_admin",
                        "onboarding_delegation_requires_multi_org",
                        "onboarding_delegation_same_org",
                        "certification_delegation_requires_tenant_admin",
                        "certification_delegation_requires_multi_org",
                        "mandator_organization_missing",
                        "on_behalf_requires_tenant_admin",
                        "on_behalf_requires_multi_org");
    }
}
