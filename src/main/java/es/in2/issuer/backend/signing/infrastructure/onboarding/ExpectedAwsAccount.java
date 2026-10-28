package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingUsageException;
import es.in2.issuer.backend.signing.domain.onboarding.RejectionReason;

import java.util.regex.Pattern;

/**
 * The AWS account the operator says the run is for ({@code --expected-aws-account}). It ties the checks of the run to
 * the environment: the account of the credentials, as STS reports it, must be that one, so a run launched with the
 * credentials of another environment is refused before it touches KMS or the database.
 */
final class ExpectedAwsAccount {

    private static final Pattern ACCOUNT_ID = Pattern.compile("^\\d{12}$");

    private ExpectedAwsAccount() {}

    /** @throws OnboardingUsageException if the value is not a 12-digit account id */
    static String parse(String value) {
        String account = value == null ? "" : value.trim();
        if (!ACCOUNT_ID.matcher(account).matches()) {
            throw new OnboardingUsageException("--expected-aws-account must be a 12-digit AWS account id");
        }
        return account;
    }

    /** @throws OnboardingRejectedException if the credentials belong to another account */
    static void requireMatch(String expected, String actual) {
        if (!expected.equals(actual)) {
            throw new OnboardingRejectedException(RejectionReason.POLICY_DENIED, "the AWS account of the credentials is "
                    + "not the expected " + expected + " (--expected-aws-account): nothing was touched");
        }
    }
}
