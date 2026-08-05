package es.in2.issuer.backend.shared.domain.exception;

/**
 * Raised when a credential catalog write references a credential_configuration_id
 * that does not exist in the global {@code CredentialProfileRegistry}. Maps to 400.
 */
public class UnknownCredentialConfigurationException extends RuntimeException {
    public UnknownCredentialConfigurationException(String message) {
        super(message);
    }
}
