package es.in2.issuer.backend.dome.domain.exception;

public class ConflictingMigrationStateException extends RuntimeException {

    public ConflictingMigrationStateException(String message) {
        super(message);
    }

    public ConflictingMigrationStateException(String message, Throwable cause) {
        super(message, cause);
    }
}

