package es.in2.issuer.backend.issuance.domain.exception;

/**
 * The issuance id is not a UUID (400 {@code BAD_REQUEST}).
 *
 * <p>One of the failures of {@code POST /api/v1/issuances/{id}/credential-offer} (EUD-295). They are
 * exceptions of their own, not the shared ones, so that only the renewal answers them as
 * {@code application/problem+json}: the other endpoints keep their responses until TD-12.
 */
public class RenewalInvalidIssuanceIdException extends RuntimeException {
    public RenewalInvalidIssuanceIdException(String message) {
        super(message);
    }
}
