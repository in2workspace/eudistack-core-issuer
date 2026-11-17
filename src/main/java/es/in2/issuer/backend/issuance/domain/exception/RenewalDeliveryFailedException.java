package es.in2.issuer.backend.issuance.domain.exception;

/**
 * The new offer could not be delivered; the previous one is still valid (503 {@code wallet_delivery_timeout}).
 *
 * <p>One of the failures of {@code POST /api/v1/issuances/{id}/credential-offer} (EUD-295). They are
 * exceptions of their own, not the shared ones, so that only the renewal answers them as
 * {@code application/problem+json}: the other endpoints keep their responses until TD-12.
 */
public class RenewalDeliveryFailedException extends RuntimeException {
    public RenewalDeliveryFailedException(String message) {
        super(message);
    }
}
