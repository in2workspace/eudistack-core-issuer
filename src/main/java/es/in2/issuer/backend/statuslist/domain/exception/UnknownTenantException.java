package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * Thrown when the tenant effective for a revocation instruction (from the message or from
 * a single-tenant deployment binding, AD-8) does not exist as an active schema in
 * {@code tenant_registry}. Always a permanent error (AC-07, EC-07): retrying will not make
 * the tenant appear.
 */
public class UnknownTenantException extends RuntimeException {

    public UnknownTenantException(String tenant) {
        super("Unknown or inactive tenant: " + tenant);
    }
}
