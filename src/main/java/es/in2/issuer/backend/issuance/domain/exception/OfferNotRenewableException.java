package es.in2.issuer.backend.issuance.domain.exception;

/**
 * The issuance is no longer a draft, or its delivery mode has no offer to renew (409 {@code offer_not_renewable}).
 *
 * <p>One of the failures of {@code POST /api/v1/issuances/{id}/credential-offer} (EUD-295). They are
 * exceptions of their own, not the shared ones, so that only the renewal answers them as
 * {@code application/problem+json}: the other endpoints keep their responses until TD-12.
 */
public class OfferNotRenewableException extends RuntimeException {
    public OfferNotRenewableException(String message) {
        super(message);
    }
}
