package es.in2.issuer.backend.dome.domain.exception;

/**
 * ES-02: Raised when the target KMS alias has not been provisioned before the import attempt.
 */
public class KmsAliasNotProvisionedException extends RuntimeException {

    public KmsAliasNotProvisionedException(String message) {
        super(message);
    }

    public KmsAliasNotProvisionedException(String message, Throwable cause) {
        super(message, cause);
    }
}

