package es.in2.issuer.backend.shared.domain.exception;

public class InvalidCredentialRequestException extends RuntimeException {
    public InvalidCredentialRequestException(String message) {
        super(message);
    }
}
