package es.in2.issuer.backend.shared.domain.exception;

import java.util.List;

/**
 * The configuration of a catalog entry is not valid (HTTP 400). {@code code} is the error type the
 * contract lists for the case: {@link #BAD_REQUEST} for a wrong body format, otherwise one of the
 * business codes ({@code field_not_in_schema}, {@code invalid_validity}, {@code no_delivery_mode},
 * {@code unknown_schema}, {@code unsupported_binding_type}). A response carries a single code and only
 * the violations of that code.
 */
public class CatalogConfigurationException extends RuntimeException {

    public static final String BAD_REQUEST = "BAD_REQUEST";

    private final String code;
    private final List<Violation> violations;

    public CatalogConfigurationException(String code, String detail, List<Violation> violations) {
        super(detail);
        this.code = code;
        this.violations = List.copyOf(violations);
    }

    public static CatalogConfigurationException badRequest(List<Violation> violations) {
        return new CatalogConfigurationException(BAD_REQUEST, "The request body is not valid", violations);
    }

    public String code() {
        return code;
    }

    public List<Violation> violations() {
        return violations;
    }

    /** {@code field} is the name of the offending attribute as the API spells it, for example {@code search_identifiers[1].field}. */
    public record Violation(String field, String message) {
    }
}
