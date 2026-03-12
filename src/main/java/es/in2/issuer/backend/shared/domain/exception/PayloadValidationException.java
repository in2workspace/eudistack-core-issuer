package es.in2.issuer.backend.shared.domain.exception;

import java.util.List;

public class PayloadValidationException extends RuntimeException {

    private final List<Violation> violations;

    public PayloadValidationException(String message, List<Violation> violations) {
        super(message);
        this.violations = violations;
    }

    public List<Violation> getViolations() {
        return violations;
    }

    public record Violation(String field, String message) {}
}
