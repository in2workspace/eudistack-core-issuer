package es.in2.issuer.backend.signing.domain.onboarding;

/**
 * An operation of the onboarding tool failed for a reason that is not a validation (KMS, database,
 * files, state). The tool ends with exit code 1. The message never includes the message of an AWS
 * exception, which can carry key ARNs and account ids.
 */
public class OnboardingFailedException extends RuntimeException {

    public OnboardingFailedException(String message) {
        super(message);
    }

    public OnboardingFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
