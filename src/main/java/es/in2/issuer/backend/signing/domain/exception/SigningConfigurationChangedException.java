package es.in2.issuer.backend.signing.domain.exception;

import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;

/**
 * The tenant's signing configuration changed after a request had already used it, for example its own
 * key was replaced while this instance still held the old one in cache (EUD-289 M4). Signing with the
 * new configuration would mix data of two certificates in one credential, so the request has to start
 * again from its first read; {@code SigningConfigScope} does that once.
 *
 * <p>Its reason is {@code KEY_UNUSABLE}, the failure that revealed the change: if it reaches the caller,
 * it reads as that.
 */
public class SigningConfigurationChangedException extends SigningException {

    public SigningConfigurationChangedException() {
        super(SigningFailureReason.KEY_UNUSABLE,
                "The signing configuration of this tenant changed while the request was using it");
    }
}
