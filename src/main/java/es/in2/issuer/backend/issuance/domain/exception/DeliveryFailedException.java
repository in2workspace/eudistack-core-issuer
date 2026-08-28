package es.in2.issuer.backend.issuance.domain.exception;

import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;

import java.util.List;

/**
 * No declared delivery mode produced a usable delivery (EUD-33 AC-06 / ES-07), or the {@code direct}
 * mode was declared and failed (ES-02).
 *
 * <p>Carries the per-mode results so the error body reports them exactly like a success body does.
 * Without that, the failure path was an information hole: a hybrid issuance whose direct leg failed
 * returned a bare 5xx while its wallet leg may already have dispatched an offer and sent an email,
 * and the audit trace collapsed to a single {@code unknown}/{@code indeterminate_result} entry.
 */
public class DeliveryFailedException extends RuntimeException {

    /**
     * {@code transient} because {@link DeliveryResult} is not {@code Serializable} and this
     * exception inherits serializability from {@link RuntimeException}. Read it through
     * {@link #deliveryResults()}, which never returns {@code null}.
     */
    private final transient List<DeliveryResult> deliveryResults;

    /**
     * The credential offer, when the wallet leg produced one before the issuance was ruled a failure.
     *
     * <p>A declared {@code direct} that fails is a failure whatever the wallet leg did, so a perfectly
     * redeemable offer can exist inside a 5xx. Dropping it there left the caller unable to show the QR
     * for a channel its own {@code delivery_results} reported as dispatched.
     */
    private final String credentialOfferUri;

    public DeliveryFailedException(String message, List<DeliveryResult> deliveryResults,
                                   String credentialOfferUri, Throwable cause) {
        super(message, cause);
        this.deliveryResults = deliveryResults == null ? List.of() : List.copyOf(deliveryResults);
        this.credentialOfferUri = credentialOfferUri;
    }

    public List<DeliveryResult> deliveryResults() {
        return deliveryResults == null ? List.of() : deliveryResults;
    }

    public String credentialOfferUri() {
        return credentialOfferUri;
    }
}
