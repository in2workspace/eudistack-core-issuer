package es.in2.issuer.backend.shared.domain.exception;

/** The issuance id in the request is not a UUID: a client error, never "not found". The id is not echoed back. */
public class MalformedIssuanceIdException extends RuntimeException {
    public MalformedIssuanceIdException() {
        super("The issuance id is not a UUID");
    }
}
