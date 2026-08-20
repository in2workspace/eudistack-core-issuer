package es.in2.issuer.backend.oidc4vci.domain.exception;

/**
 * Raised when a /credential request uses the credential_identifier addressing mode
 * (OID4VCI 1.0 SS8.2). This Issuer never returns authorization_details with
 * credential_identifiers from the Token Response, so any credential_identifier a client
 * sends is by definition unrecognized. Maps to 400.
 */
public class UnknownCredentialIdentifierException extends RuntimeException {
    public UnknownCredentialIdentifierException(String message) {
        super(message);
    }
}
