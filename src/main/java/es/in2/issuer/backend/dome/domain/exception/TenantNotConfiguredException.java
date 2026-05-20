package es.in2.issuer.backend.dome.domain.exception;

/**
 * Exception thrown when the requested tenant is not configured in the system.
 * This will be mapped to HTTP 503 Service Unavailable.
 */
public class TenantNotConfiguredException extends RuntimeException {

    public TenantNotConfiguredException(String message) {
        super(message);
    }

    public TenantNotConfiguredException(String message, Throwable cause) {
        super(message, cause);
    }
}
