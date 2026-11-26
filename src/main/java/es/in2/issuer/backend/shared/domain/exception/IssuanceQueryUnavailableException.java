package es.in2.issuer.backend.shared.domain.exception;

/**
 * The issuance processes could not be read for a query (EUD-255 AD-3): a schema of a tenant or the registry of
 * tenants failed. The request answers {@code 500 internal_error} and returns nothing, since a page missing the
 * processes of one tenant would read as complete. The message says nothing of the query.
 */
public class IssuanceQueryUnavailableException extends RuntimeException {

    public IssuanceQueryUnavailableException(Throwable cause) {
        super("The issuance processes could not be read", cause);
    }
}
