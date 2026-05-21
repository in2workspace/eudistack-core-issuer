package es.in2.issuer.backend.dome.domain.exception;

/**
 * ES-09: Raised when the SHA-256 hash of the re-issued credential's canonical JSON
 * does not match the hash of the original credential, indicating data integrity loss.
 */
public class HashMismatchException extends RuntimeException {

    public HashMismatchException(String message) {
        super(message);
    }

    public HashMismatchException(String message, Throwable cause) {
        super(message, cause);
    }
}

