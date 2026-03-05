package es.in2.issuer.backend.shared.domain.exception;

public class CredentialTypeUnsupportedException extends RuntimeException {

    public CredentialTypeUnsupportedException(String message) {
        super(message);
    }

}
