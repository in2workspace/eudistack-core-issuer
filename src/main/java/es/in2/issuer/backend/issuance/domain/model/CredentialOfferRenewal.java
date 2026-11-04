package es.in2.issuer.backend.issuance.domain.model;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;

/**
 * Outcome of renewing the credential offer of a draft issuance (EUD-295).
 *
 * @param mode               the single mode the new offer was delivered with ({@code ui} or {@code email})
 * @param credentialOfferUri the new offer link with {@code ui}; {@code null} with {@code email}
 */
public record CredentialOfferRenewal(DeliveryMode mode, String credentialOfferUri) {
}
