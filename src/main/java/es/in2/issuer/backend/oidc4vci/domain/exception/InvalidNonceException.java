package es.in2.issuer.backend.oidc4vci.domain.exception;

/**
 * OID4VCI 1.0 Final §8.3.1.2 {@code invalid_nonce}: a key proof carries a c_nonce that the
 * Issuer does not recognize or that has expired. Distinct from {@code invalid_proof}, which
 * covers a proof that is missing, malformed, or carries no c_nonce at all — the Wallet's
 * recovery differs: here it should fetch a fresh nonce and retry.
 */
public class InvalidNonceException extends RuntimeException {
    public InvalidNonceException(String message) {
        super(message);
    }
}
