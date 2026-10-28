package es.in2.issuer.backend.signing.domain.onboarding;

/**
 * What the policy of {@code prepare} was, kept in the state so that {@code import} cannot run with a laxer or a
 * different one. It holds no secret: whether the production checks applied, the SHA-256 of the agreed CA and the
 * expected organizationIdentifier of the tenant.
 *
 * @param production                whether the production checks applied
 * @param trustAnchorSha256         SHA-256 of the DER trust anchor, hexadecimal; {@code null} if none was given
 * @param expectedOrganizationIdentifier the organizationIdentifier that was required; {@code null} if none
 */
public record PolicySummary(boolean production, String trustAnchorSha256, String expectedOrganizationIdentifier) {

    /**
     * @return why {@code current} is laxer than or different from this policy, or {@code null} if it is the same or
     *         stricter. A stricter import (production checks that {@code prepare} did not apply) is accepted.
     */
    public String whyNotCoveredBy(PolicySummary current) {
        if (production && !current.production()) {
            return "prepare ran with the production checks and import without them";
        }
        if (trustAnchorSha256 != null && !trustAnchorSha256.equals(current.trustAnchorSha256())) {
            return "the trust anchor is not the one of prepare";
        }
        if (expectedOrganizationIdentifier != null
                && !expectedOrganizationIdentifier.equals(current.expectedOrganizationIdentifier())) {
            return "the expected organizationIdentifier is not the one of prepare";
        }
        return null;
    }
}
