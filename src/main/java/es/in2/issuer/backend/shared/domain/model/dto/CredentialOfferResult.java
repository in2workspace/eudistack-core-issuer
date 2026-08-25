package es.in2.issuer.backend.shared.domain.model.dto;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import lombok.Builder;

import java.util.Map;

/**
 * Outcome of dispatching one credential offer across the OID4VCI delivery channels.
 *
 * <p>{@code failedModes} maps each channel whose transport actually failed to its error detail.
 * A declared channel absent from the map was dispatched: the map is the discriminator, so a
 * channel is never reported as failed just because it shared a dispatch with one that was
 * (EUD-33 EC-05). {@code credentialOfferUri} is present whenever a channel that returns the
 * offer identifier was declared -- the offer is cached and redeemable before any transport runs,
 * so a mail server outage must not discard it.
 */
@Builder
public record CredentialOfferResult(
        String credentialOfferUri,
        Map<DeliveryMode, String> failedModes
) {

    public CredentialOfferResult {
        failedModes = failedModes == null ? Map.of() : Map.copyOf(failedModes);
    }

    /** Every declared channel dispatched. Kept for the callers that only care about the URI. */
    public CredentialOfferResult(String credentialOfferUri) {
        this(credentialOfferUri, Map.of());
    }
}
