package es.in2.issuer.backend.issuance.domain.exception;

/**
 * The issuance does not exist or is outside the requester's scope; both answer the same (404 {@code issuance_not_found}).
 *
 * <p>One of the failures of {@code POST /api/v1/issuances/{id}/credential-offer} (EUD-295). They are
 * exceptions of their own, not the shared ones, so that only the renewal answers them as
 * {@code application/problem+json}: the other endpoints keep their responses until TD-12.
 */
public class RenewalIssuanceNotFoundException extends RuntimeException {
    public RenewalIssuanceNotFoundException(String message) {
        super(message);
    }
}
