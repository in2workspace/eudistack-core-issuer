package es.in2.issuer.backend.issuance.domain.exception;

/**
 * The stored process cannot be decided as an issuance: its type is no longer known or its content
 * cannot be read, so what the new offer would grant is unknown and the renewal is denied (fail
 * closed). Answered as any other denial (403 {@code insufficient_permission}); the decision point
 * never saw it, so the renewal audits it itself.
 */
public class RenewalContentNotDecidableException extends RenewalPermissionDeniedException {
    public RenewalContentNotDecidableException(String message) {
        super(message);
    }
}
