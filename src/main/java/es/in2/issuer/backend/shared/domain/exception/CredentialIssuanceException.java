package es.in2.issuer.backend.shared.domain.exception;

public class CredentialIssuanceException extends RuntimeException {

    public CredentialIssuanceException(String message) {
        super(message);
    }

    public CredentialIssuanceException(String message, Throwable cause) {
        super(message, cause);
    }

}
