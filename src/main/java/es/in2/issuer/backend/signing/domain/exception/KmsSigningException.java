package es.in2.issuer.backend.signing.domain.exception;

import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;

/**
 * A KMS signing operation failed. Messages never carry key material or digests.
 */
public class KmsSigningException extends SigningException {

    public KmsSigningException(SigningFailureReason reason, String message) {
        super(reason, message);
    }

    public KmsSigningException(SigningFailureReason reason, String message, Throwable cause) {
        super(reason, message, cause);
    }
}
