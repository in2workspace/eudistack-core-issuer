package es.in2.issuer.backend.issuance.domain.exception;

/**
 * The access token was issued for another tenant than the one of the request (403 {@code tenant_mismatch}).
 *
 * <p>One of the failures of {@code POST /api/v1/issuances/{id}/credential-offer} (EUD-295). They are
 * exceptions of their own, not the shared ones, so that only the renewal answers them as
 * {@code application/problem+json}: the other endpoints keep their responses until TD-12.
 */
public class RenewalTenantMismatchException extends RuntimeException {
    public RenewalTenantMismatchException(String message) {
        super(message);
    }
}
