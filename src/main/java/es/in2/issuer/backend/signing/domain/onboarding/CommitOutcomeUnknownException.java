package es.in2.issuer.backend.signing.domain.onboarding;

/**
 * The database did not answer the commit of the onboarding transaction: the new configuration may or may
 * not be active. The KMS key must not be disabled in that case, because it may already be the active one;
 * the operator checks {@code tenant_signing_config} and, if the row is not there, retires the key by hand.
 */
public class CommitOutcomeUnknownException extends OnboardingFailedException {

    public CommitOutcomeUnknownException(String message, Throwable cause) {
        super(message, cause);
    }
}
