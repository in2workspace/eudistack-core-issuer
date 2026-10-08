package es.in2.issuer.backend.shared.domain.model.dto;

import lombok.Builder;

import java.time.Instant;

/**
 * A credential offer held in the transient store, together with its lifecycle state.
 *
 * @param expiresAt instant after which the offer can no longer be retrieved by the Wallet
 * @param consumed  whether the Wallet has already retrieved it (credential offers are single-use)
 */
@Builder(toBuilder = true)
public record CredentialOfferData(
        CredentialOffer credentialOffer,
        String credentialEmail,
        String txCode,
        Instant expiresAt,
        boolean consumed
) {

    /**
     * An offer is redeemable only once and only before it expires. An offer without
     * {@code expiresAt} is treated as expired: its lifetime is unknown, so it must not be served.
     */
    public boolean isRedeemableAt(Instant now) {
        return !consumed && expiresAt != null && now.isBefore(expiresAt);
    }

    public CredentialOfferData markConsumed() {
        return toBuilder().consumed(true).build();
    }
}