package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * The attestation cannot be revoked: its process is not Valid, or it has no position in a status
 * list to mark (EUD-247 §5). Nothing is written.
 */
public class NotRevocableException extends RuntimeException {

    public NotRevocableException(String message) {
        super(message);
    }
}
