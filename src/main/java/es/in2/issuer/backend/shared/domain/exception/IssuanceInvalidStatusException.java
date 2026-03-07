package es.in2.issuer.backend.shared.domain.exception;

public class IssuanceInvalidStatusException extends RuntimeException {
    public IssuanceInvalidStatusException(String message) {
        super(message);
    }
}
