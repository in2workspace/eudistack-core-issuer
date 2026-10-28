package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingUsageException;
import es.in2.issuer.backend.signing.domain.onboarding.RejectionReason;
import lombok.extern.slf4j.Slf4j;

import java.util.regex.Pattern;

/**
 * The AWS account the operator says the run is for ({@code --expected-aws-account}). It ties the checks of the run to
 * the environment: the account of the credentials, as STS reports it, must be that one, so a run launched with the
 * credentials of another environment is refused before it touches KMS or the database.
 */
@Slf4j
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

    /**
     * A run with the credentials of another account touches nothing and leaves no audit event, only a warn line with both
     * accounts, so that whoever looks at the log can tell which credentials were used.
     *
     * @throws OnboardingRejectedException if the credentials belong to another account
     */
    static void requireMatch(String expected, String actual) {
        if (!expected.equals(actual)) {
            log.warn("The AWS account of the credentials is {} (STS GetCallerIdentity), not the expected {} "
                    + "(--expected-aws-account): the run is refused and nothing was touched", actual, expected);
            throw new OnboardingRejectedException(RejectionReason.POLICY_DENIED, "the AWS account of the credentials is "
                    + "not the expected " + expected + " (--expected-aws-account): nothing was touched");
        }
    }
}
