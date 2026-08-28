package es.in2.issuer.backend.statuslist.domain.spi;

import reactor.core.publisher.Mono;

/**
 * Message-level idempotency port for the revocation-instruction inbound channel (AD-4).
 * <p>
 * Backs NFR-R-02 (zero observable side effects on redelivery) across two windows:
 * redelivery after successful completion, and redelivery overlapping an in-flight
 * delivery of the same {@code messageId}. Implementations must make {@link #claim}
 * atomic (e.g. an insert-or-nothing on a primary key) so that concurrent deliveries
 * of the same message — possibly across replicas — resolve to a single winner.
 */
public interface RevocationInstructionInbox {

    /**
     * Atomically attempts to claim the given {@code messageId} for processing.
     *
     * @return {@link ClaimResult#CLAIMED} if this call owns the processing of the message;
     *         {@link ClaimResult#ALREADY_PROCESSED} if the message reached a terminal state
     *         (processed or skipped) in a previous delivery;
     *         {@link ClaimResult#IN_PROGRESS} if another delivery currently owns an unexpired
     *         claim on the same message.
     */
    Mono<ClaimResult> claim(String messageId, String issuanceId);

    /**
     * Marks the claimed message as successfully processed (the domain revocation effect
     * was applied).
     */
    Mono<Void> markProcessed(String messageId);

    /**
     * Marks the claimed message as skipped: the instruction was handled, but no domain
     * effect was applied because the credential was no longer revocable.
     */
    Mono<Void> markSkipped(String messageId);

    /**
     * Releases a claim that failed with neither a successful processing nor a "no longer
     * revocable" skip — an in-process retry (AD-5) or a genuine redelivery must be able to
     * re-claim immediately rather than wait out the full {@code IN_PROGRESS} lease. Without
     * this, a transient failure (ES-04) after a successful claim would make the very next
     * retry see {@link ClaimResult#IN_PROGRESS} against its own abandoned attempt, defeating
     * AC-09's "recovers within the configured retries" guarantee. Idempotent: releasing a
     * {@code messageId} with no claim, or one already closed, is a no-op.
     */
    Mono<Void> release(String messageId);

    enum ClaimResult {
        CLAIMED,
        ALREADY_PROCESSED,
        IN_PROGRESS
    }
}
