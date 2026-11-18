package es.in2.issuer.backend.issuance.domain.exception;

public class InvalidValidityException extends RuntimeException {
    public InvalidValidityException(String message) {
        super(message);
    }
}
