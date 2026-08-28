package es.in2.issuer.backend.issuance.domain.exception;

public class InvalidHolderKeyException extends RuntimeException {
    public InvalidHolderKeyException(String message) {
        super(message);
    }
}
