package es.in2.issuer.backend.shared.domain.exception;

/**
 * The trace of a query or of a detail could not be staged (EUD-255 AD-7): the request answers
 * {@code 500 internal_error} and returns no data, since a read that leaves no trace is not served.
 * The message says nothing of the entry, which carries personal data.
 */
public class AuditTrailUnavailableException extends RuntimeException {

    public AuditTrailUnavailableException(Throwable cause) {
        super("The audit trail of the operation could not be staged", cause);
    }
}
