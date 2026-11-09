package es.in2.issuer.backend.shared.domain.exception;

/** The tenant's catalog has no entry for the credential configuration id (HTTP 404). */
public class CatalogEntryNotFoundException extends RuntimeException {
    public CatalogEntryNotFoundException(String credentialConfigurationId) {
        super("The catalog has no entry '" + credentialConfigurationId + "'");
    }
}
