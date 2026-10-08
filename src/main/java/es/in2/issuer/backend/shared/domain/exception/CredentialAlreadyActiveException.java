package es.in2.issuer.backend.shared.domain.exception;

public class CredentialAlreadyActiveException extends RuntimeException {
    public CredentialAlreadyActiveException(String message) {
        super(message);
    }
}
