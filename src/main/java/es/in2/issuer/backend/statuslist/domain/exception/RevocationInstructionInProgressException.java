package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * Thrown when a revocation instruction is claimed by another in-flight delivery of the
 * same {@code messageId} (EC-03). Retryable by construction: the owning delivery is
 * expected to complete (or its claim to expire, NFR-S-225-04) shortly, so the inbound
 * adapter should redeliver with backoff rather than route to the DLQ.
 */
public class RevocationInstructionInProgressException extends RuntimeException {

    public RevocationInstructionInProgressException(String messageId) {
        super("Revocation instruction " + messageId + " is already being processed by another delivery");
    }
}
