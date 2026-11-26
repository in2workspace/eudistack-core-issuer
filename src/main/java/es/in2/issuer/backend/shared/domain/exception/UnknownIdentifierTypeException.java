package es.in2.issuer.backend.shared.domain.exception;

/**
 * A search by identifier whose type no catalogue entry of the tenant declares as a search identifier (EUD-255
 * FR-05, contract {@code unknown_identifier_type}). The message names neither the type nor the value.
 */
public class UnknownIdentifierTypeException extends RuntimeException {

    public UnknownIdentifierTypeException() {
        super("No catalogue entry of the tenant declares that search identifier");
    }
}
