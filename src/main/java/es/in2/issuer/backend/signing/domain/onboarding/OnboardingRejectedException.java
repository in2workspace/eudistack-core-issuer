package es.in2.issuer.backend.signing.domain.onboarding;

/**
 * A validation refused the onboarding. The current signing configuration of the tenant is untouched.
 * The tool ends with exit code 2 and prints the message, so it must say what was wrong in terms the
 * operator can act on, and must never carry secrets.
 */
public class OnboardingRejectedException extends RuntimeException {

    private final RejectionReason reason;

    public OnboardingRejectedException(RejectionReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RejectionReason getReason() {
        return reason;
    }
}
