package es.in2.issuer.backend.shared.domain.exception;

/**
 * An entry for the same credential type or the same schema already exists in the tenant's catalog.
 */
public class CatalogEntryAlreadyExistsException extends RuntimeException {
    public CatalogEntryAlreadyExistsException(String credentialConfigurationId, Throwable cause) {
        super("A catalog entry already exists for '" + credentialConfigurationId + "'", cause);
    }
}
