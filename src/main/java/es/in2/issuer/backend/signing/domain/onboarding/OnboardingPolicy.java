package es.in2.issuer.backend.signing.domain.onboarding;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

/**
 * The checks of an onboarding that depend on the environment.
 *
 * @param production                    the production checks: the certificate is not self-signed, and the
 *                                      trust anchor and the organization identifier are mandatory. They are the
 *                                      default of the tool; {@code --non-production} turns them off
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
            throw new OnboardingUsageException("the production checks need the trust anchor (the CA agreed with the tenant): "
                    + "--trust-anchor, or --non-production outside production");
        }
        if (production && expectedOrganizationIdentifier == null) {
            throw new OnboardingUsageException("the production checks need the expected organizationIdentifier of the "
                    + "tenant: --expected-org-id, or --non-production outside production");
        }
    }

    /** No production checks and no trust anchor: STG and local environments. */
    public static OnboardingPolicy nonProduction() {
        return new OnboardingPolicy(false, null, null);
    }

    /** What {@code import} later compares with: see {@link PolicySummary}. */
    public PolicySummary summary() {
        return new PolicySummary(production, trustAnchor == null ? null : sha256Hex(trustAnchor),
                expectedOrganizationIdentifier);
    }

    private static String sha256Hex(X509Certificate certificate) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("The trust anchor cannot be hashed", e);
        }
    }
}
