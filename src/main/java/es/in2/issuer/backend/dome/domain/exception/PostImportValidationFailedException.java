package es.in2.issuer.backend.dome.domain.exception;

/**
 * ES-07: Raised when the post-import signature produced by the KMS cannot be verified
 * against the public key of the imported key material.
 */
public class PostImportValidationFailedException extends RuntimeException {

    public PostImportValidationFailedException(String message) {
        super(message);
    }

    public PostImportValidationFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}

