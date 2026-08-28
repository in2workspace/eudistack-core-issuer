package es.in2.issuer.backend.shared.domain.exception;

/**
 * Raised when the credential catalog of the current tenant has no enabled
 * credential_configuration_id — either the tenant was never configured or every
 * stored id is unknown to the global {@code CredentialProfileRegistry}. Maps to 404.
 */
public class CredentialCatalogNotConfiguredException extends RuntimeException {
    public CredentialCatalogNotConfiguredException(String message) {
        super(message);
    }
}
