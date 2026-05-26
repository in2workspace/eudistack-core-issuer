package es.in2.issuer.backend.dome.domain.exception;

public class KmsAliasNotProvisionedException extends RuntimeException {

    public KmsAliasNotProvisionedException(String message) {
        super(message);
    }

    public KmsAliasNotProvisionedException(String message, Throwable cause) {
        super(message, cause);
    }
}

