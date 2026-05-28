package es.in2.issuer.backend.dome.domain.exception;

public class HashMismatchException extends RuntimeException {

    public HashMismatchException(String message) {
        super(message);
    }

    public HashMismatchException(String message, Throwable cause) {
        super(message, cause);
    }
}

