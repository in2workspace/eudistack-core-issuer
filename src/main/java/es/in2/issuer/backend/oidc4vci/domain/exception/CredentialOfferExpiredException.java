package es.in2.issuer.backend.oidc4vci.domain.exception;

public class CredentialOfferExpiredException extends RuntimeException {
    public CredentialOfferExpiredException(String message) {
        super(message);
    }
}
