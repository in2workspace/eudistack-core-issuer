package es.in2.issuer.backend.issuance.domain.exception;

/**
 * The requester may not issue, or may not write (403 {@code insufficient_permission}).
 *
 * <p>One of the failures of {@code POST /api/v1/issuances/{id}/credential-offer} (EUD-295). They are
 * exceptions of their own, not the shared ones, so that only the renewal answers them as
 * {@code application/problem+json}: the other endpoints keep their responses until TD-12.
 */
public class RenewalPermissionDeniedException extends RuntimeException {
    public RenewalPermissionDeniedException(String message) {
        super(message);
    }
}
