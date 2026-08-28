package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * Thrown when a revocation instruction cannot be mapped to a valid domain command:
 * missing/invalid required fields, or no {@code messageId} available from either the
 * message body or the AMQP {@code message-id} property (EC-01). Always a permanent
 * error (ES-01) — the inbound adapter routes it to the DLQ without retrying.
 */
public class InvalidRevocationInstructionException extends RuntimeException {

    public InvalidRevocationInstructionException(String message) {
        super(message);
    }
}
