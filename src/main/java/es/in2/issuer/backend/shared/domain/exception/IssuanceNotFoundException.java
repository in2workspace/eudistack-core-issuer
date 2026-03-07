package es.in2.issuer.backend.shared.domain.exception;

public class IssuanceNotFoundException extends RuntimeException {
    public IssuanceNotFoundException(String message) {
        super(message);
    }
}
