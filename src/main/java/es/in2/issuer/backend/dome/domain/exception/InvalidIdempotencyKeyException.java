package es.in2.issuer.backend.dome.domain.exception;

/**
 * Exception thrown when the provided idempotency key is invalid.
 * This will be mapped to HTTP 400 Bad Request.
 */
public class InvalidIdempotencyKeyException extends RuntimeException {

    public InvalidIdempotencyKeyException(String message) {
        super(message);
    }

    public InvalidIdempotencyKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
