package es.in2.issuer.backend.signing.domain.onboarding;

import java.security.cert.X509Certificate;

/**
 * The checks of an onboarding that depend on the environment.
 *
 * @param production                    adds the production checks: the certificate is not self-signed, and the
 *                                      trust anchor and the organization identifier are mandatory
 * @param trustAnchor                   the CA agreed with the tenant (root or intermediate) the chain must end in;
 *                                      checked whenever it is given
 * @param expectedOrganizationIdentifier organizationIdentifier of the tenant, e.g. {@code VATES-Q0000000X}, that the
 *                                      leaf must carry; checked whenever it is given
 */
public record OnboardingPolicy(
        boolean production,
        X509Certificate trustAnchor,
        String expectedOrganizationIdentifier
) {

    public OnboardingPolicy {
        if (expectedOrganizationIdentifier != null && expectedOrganizationIdentifier.isBlank()) {
            expectedOrganizationIdentifier = null;
        }
        if (production && trustAnchor == null) {
            throw new IllegalArgumentException("production requires the trust anchor (the CA agreed with the tenant)");
        }
        if (production && expectedOrganizationIdentifier == null) {
            throw new IllegalArgumentException("production requires the expected organizationIdentifier of the tenant");
        }
    }

    /** No production checks and no trust anchor: STG and local environments. */
    public static OnboardingPolicy nonProduction() {
        return new OnboardingPolicy(false, null, null);
    }
}
