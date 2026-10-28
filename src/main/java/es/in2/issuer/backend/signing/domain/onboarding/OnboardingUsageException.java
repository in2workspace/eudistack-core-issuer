package es.in2.issuer.backend.signing.domain.onboarding;

/**
 * The tool was called with arguments, environment or inputs it cannot work with. The tool ends with exit code 64
 * and the message, which says what to correct. It is the only exception that is a usage error: any other
 * {@link IllegalArgumentException} is a bug or a failure of a library and ends with exit code 1.
 */
public class OnboardingUsageException extends RuntimeException {

    public OnboardingUsageException(String message) {
        super(message);
    }
}
