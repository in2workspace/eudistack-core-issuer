package es.in2.issuer.backend.issuance.domain.exception;

public class MissingRequiredDataException extends RuntimeException {
    public MissingRequiredDataException(String message) {
        super(message);
    }
}
