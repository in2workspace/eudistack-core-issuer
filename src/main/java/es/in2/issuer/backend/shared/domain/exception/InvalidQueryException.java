package es.in2.issuer.backend.shared.domain.exception;

import java.util.List;

/**
 * A query of the query API that is not valid (EUD-255): {@code 400 invalid_request} with one
 * violation per field. Neither the message nor a violation repeats the value the client sent, which
 * may be personal data (AD-5).
 */
public class InvalidQueryException extends RuntimeException {

    private final transient List<Violation> violations;

    public InvalidQueryException(List<Violation> violations) {
        super("The query is not valid");
        this.violations = List.copyOf(violations);
    }

    public static InvalidQueryException of(String field, String message) {
        return new InvalidQueryException(List.of(new Violation(field, message)));
    }

    public List<Violation> violations() {
        return violations;
    }

    public record Violation(String field, String message) {
    }
}
