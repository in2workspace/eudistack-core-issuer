package es.in2.issuer.backend.shared.domain.model.entities;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/** EUD-255 AD-2: the last change moves with the state, and only with it. */
class IssuanceLastChangedAtTest {

    private static final Instant BEFORE = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void aChangeOfStateMovesTheLastChange() {
        Issuance issuance = Issuance.builder()
                .credentialStatus(CredentialStatusEnum.VALID)
                .lastChangedAt(BEFORE)
                .build();
        Instant start = Instant.now();

        issuance.setCredentialStatus(CredentialStatusEnum.REVOKED);

        assertThat(issuance.getCredentialStatus()).isEqualTo(CredentialStatusEnum.REVOKED);
        assertThat(issuance.getLastChangedAt()).isAfterOrEqualTo(start);
    }

    @Test
    void settingTheSameStateKeepsTheLastChange() {
        Issuance issuance = Issuance.builder()
                .credentialStatus(CredentialStatusEnum.VALID)
                .lastChangedAt(BEFORE)
                .build();

        issuance.setCredentialStatus(CredentialStatusEnum.VALID);

        assertThat(issuance.getLastChangedAt()).isEqualTo(BEFORE);
    }

    @Test
    void buildingAProcessIsNotAChangeOfState() {
        Issuance issuance = Issuance.builder()
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .build();

        assertThat(issuance.getLastChangedAt()).isNull();
    }

    @Test
    void otherWritesKeepTheLastChange() {
        Issuance issuance = Issuance.builder()
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .lastChangedAt(BEFORE)
                .build();

        issuance.setDeliveryAttemptedAt(Instant.now());
        issuance.setCredentialOfferRefreshToken("renewed");

        assertThat(issuance.getLastChangedAt()).isEqualTo(BEFORE);
    }
}
