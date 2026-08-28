package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * Thrown when the public issuer base URL a status list was signed against (AD-2)
 * cannot be derived from the persisted, already-signed list. Fail-closed: callers
 * must treat this as a permanent error, never fall back to a guessed or configured
 * value.
 */
public class StatusListPublicBaseUrlNotResolvableException extends RuntimeException {

    public StatusListPublicBaseUrlNotResolvableException(String message) {
        super(message);
    }
}
