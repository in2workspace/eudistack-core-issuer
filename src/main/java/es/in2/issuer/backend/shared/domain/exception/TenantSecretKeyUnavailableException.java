package es.in2.issuer.backend.shared.domain.exception;

/**
 * The secret key of the tenant is not configured or cannot be read (EUD-267). An issuance of a type with search
 * identifiers fails with it, before anything is written, and is answered 500: a process is never stored without
 * its fingerprints. The message names the tenant, never the key or its location.
 */
public class TenantSecretKeyUnavailableException extends RuntimeException {

    public TenantSecretKeyUnavailableException(String message) {
        super(message);
    }

    public TenantSecretKeyUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
