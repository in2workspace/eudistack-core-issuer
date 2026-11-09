package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * The attestation could not be marked in its status list (sealing or commit failed, or the list
 * kept changing under every attempt). Neither the list nor the process changed, so the client can
 * retry (EUD-247 AC-08).
 */
public class StatusListUnavailableException extends RuntimeException {

    public StatusListUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
