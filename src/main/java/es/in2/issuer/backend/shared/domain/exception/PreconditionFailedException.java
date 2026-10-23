package es.in2.issuer.backend.shared.domain.exception;

/** {@code If-Match} does not match the current version of the entry (HTTP 412). */
public class PreconditionFailedException extends RuntimeException {
    public PreconditionFailedException(String message) {
        super(message);
    }
}
