package es.in2.issuer.backend.issuance.domain.exception;

/** The {@code organization} of an issuance is not an organization of the tenant (EUD-254 FR-12, AC-18). */
public class UnknownOrganizationException extends RuntimeException {
    public UnknownOrganizationException(String message) {
        super(message);
    }
}
