package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * Thrown when {@code R2dbcRevocationInstructionInbox.claim} exhausts its bounded number
 * of internal retries (the lost-race and vanished-row recovery paths) without reaching a
 * terminal {@code ClaimResult}. Not expected in practice — each individual retry only
 * happens after losing a race to a concurrent claim/release on the same row, which
 * resolves the row's state one way or another; this is a formal ceiling against an
 * adversarial or pathological sequence of repeated collisions (code review, EUD-225 PR
 * #147, MEDIUM-2), not a scenario this Story's tests reproduce. Unclassified by
 * {@code RevocationInstructionErrorClassifier}, so it is retried at the AMQP level
 * (backoff, then DLQ) like any other unexpected failure, rather than looping DB round-trips
 * indefinitely in-process.
 */
public class RevocationInstructionClaimExhaustedException extends RuntimeException {

    public RevocationInstructionClaimExhaustedException(String message) {
        super(message);
    }
}
