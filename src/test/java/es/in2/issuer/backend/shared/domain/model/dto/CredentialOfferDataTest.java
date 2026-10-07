package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialOfferDataTest {

    private static final Instant NOW = Instant.parse("2026-09-30T10:00:00Z");

    @Test
    void CredentialOfferData_isRedeemableAt_trueBeforeExpiry() {
        CredentialOfferData data = CredentialOfferData.builder().expiresAt(NOW.plusSeconds(1)).build();

        assertThat(data.isRedeemableAt(NOW)).isTrue();
    }

    @Test
    void CredentialOfferData_isRedeemableAt_falseAtExactExpiry() {
        CredentialOfferData data = CredentialOfferData.builder().expiresAt(NOW).build();

        assertThat(data.isRedeemableAt(NOW)).isFalse();
    }

    @Test
    void CredentialOfferData_isRedeemableAt_falseAfterExpiry() {
        CredentialOfferData data = CredentialOfferData.builder().expiresAt(NOW.minusSeconds(1)).build();

        assertThat(data.isRedeemableAt(NOW)).isFalse();
    }

    @Test
    void CredentialOfferData_isRedeemableAt_falseWhenConsumed() {
        CredentialOfferData data = CredentialOfferData.builder()
                .expiresAt(NOW.plusSeconds(60))
                .consumed(true)
                .build();

        assertThat(data.isRedeemableAt(NOW)).isFalse();
    }

    @Test
    void CredentialOfferData_isRedeemableAt_falseWhenExpiryUnknown() {
        CredentialOfferData data = CredentialOfferData.builder().build();

        assertThat(data.isRedeemableAt(NOW)).isFalse();
    }

    @Test
    void CredentialOfferData_markConsumed_keepsPayloadAndSetsConsumed() {
        CredentialOffer offer = CredentialOffer.builder().credentialIssuer("https://issuer.example").build();
        CredentialOfferData data = CredentialOfferData.builder()
                .credentialOffer(offer)
                .credentialEmail("a@example.com")
                .txCode("1234")
                .expiresAt(NOW)
                .build();

        assertThat(data.markConsumed())
                .isEqualTo(data.toBuilder().consumed(true).build());
    }
}