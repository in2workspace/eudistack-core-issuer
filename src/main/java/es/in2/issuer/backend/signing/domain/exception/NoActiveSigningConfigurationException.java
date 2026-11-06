package es.in2.issuer.backend.signing.domain.exception;

/** The active tenant has no signing configuration, so there is nothing to sign with. */
public class NoActiveSigningConfigurationException extends SigningException {

    public NoActiveSigningConfigurationException(String message) {
        super(message);
    }
}
