package es.in2.issuer.backend.dome.domain.exception;

public class PostImportValidationFailedException extends RuntimeException {

    public PostImportValidationFailedException(String message) {
        super(message);
    }

    public PostImportValidationFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}

