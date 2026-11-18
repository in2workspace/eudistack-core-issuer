package es.in2.issuer.backend.issuance.domain.exception;

public class InvalidGrantTypeException extends RuntimeException {
    public InvalidGrantTypeException(String message) {
        super(message);
    }
}
