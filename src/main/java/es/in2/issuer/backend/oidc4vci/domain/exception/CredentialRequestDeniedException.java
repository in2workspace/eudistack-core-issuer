package es.in2.issuer.backend.oidc4vci.domain.exception;

/**
 * OID4VCI 1.0 Final §8.3.1.2 {@code credential_request_denied}: the Credential Request was
 * well-formed and authorized, but the Issuer will not serve it. The Wallet must treat this as
 * unrecoverable — retrying cannot succeed.
 */
public class CredentialRequestDeniedException extends RuntimeException {
    public CredentialRequestDeniedException(String message) {
        super(message);
    }
}
