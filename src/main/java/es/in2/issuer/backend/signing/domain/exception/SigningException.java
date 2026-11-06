package es.in2.issuer.backend.signing.domain.exception;

import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;

/**
 * A signing operation failed. Every instance carries a {@link SigningFailureReason};
 * constructors without one default to {@link SigningFailureReason#OTHER}.
 */
public class SigningException extends RuntimeException {

    private final SigningFailureReason reason;

    public SigningException(String message) {
        this(SigningFailureReason.OTHER, message);
    }

    public SigningException(String message, Throwable cause) {
        this(SigningFailureReason.OTHER, message, cause);
    }

    public SigningException(SigningFailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public SigningException(SigningFailureReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public SigningFailureReason getReason() {
        return reason;
    }
}
