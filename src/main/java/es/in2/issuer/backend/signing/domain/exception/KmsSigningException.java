package es.in2.issuer.backend.signing.domain.exception;

import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;

/**
 * A KMS signing operation failed. Messages never carry key material or digests.
 */
public class KmsSigningException extends SigningException {

    private final SigningFailureReason reason;

    public KmsSigningException(SigningFailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public KmsSigningException(SigningFailureReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public SigningFailureReason getReason() {
        return reason;
    }
}
