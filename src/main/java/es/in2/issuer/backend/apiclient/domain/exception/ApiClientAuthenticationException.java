package es.in2.issuer.backend.apiclient.domain.exception;

/**
 * Fail-closed, anti-enumeration signal: raised for every denial at the
 * client_credentials token endpoint (unknown client_id, wrong secret,
 * non-ACTIVE status, or a repository failure). Callers MUST translate this
 * into a single uniform {@code invalid_client} response (ES-03,
 * NFR-S-EUD75-02) regardless of the underlying cause — the cause is only
 * ever surfaced via the audit trail, never in the response to the caller.
 */
public class ApiClientAuthenticationException extends RuntimeException {

    private ApiClientAuthenticationException() {
        super("invalid_client");
    }

    public static ApiClientAuthenticationException invalidClient() {
        return new ApiClientAuthenticationException();
    }
}
