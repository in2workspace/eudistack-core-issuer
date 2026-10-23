package es.in2.issuer.backend.shared.domain.exception;

/** {@code If-Match} is missing, or is {@code *}, which does not protect against concurrent changes (HTTP 428). */
public class PreconditionRequiredException extends RuntimeException {
    public PreconditionRequiredException(String message) {
        super(message);
    }
}
