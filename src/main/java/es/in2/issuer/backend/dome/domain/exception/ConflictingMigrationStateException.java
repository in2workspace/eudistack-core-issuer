package es.in2.issuer.backend.dome.domain.exception;

/**
 * ES-04: Raised when an attempt is made to activate Plan-B re-issuance while the migration
 * record already holds a terminal {@code PLAN_A_OK} status.
 */
public class ConflictingMigrationStateException extends RuntimeException {

    public ConflictingMigrationStateException(String message) {
        super(message);
    }

    public ConflictingMigrationStateException(String message, Throwable cause) {
        super(message, cause);
    }
}

