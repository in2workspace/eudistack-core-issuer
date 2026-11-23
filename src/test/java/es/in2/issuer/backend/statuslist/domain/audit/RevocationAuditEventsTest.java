package es.in2.issuer.backend.statuslist.domain.audit;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Holder;
import es.in2.issuer.backend.statuslist.domain.audit.RevocationAuditEvents.Origin;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class RevocationAuditEventsTest {

    private static final String ISSUANCE_ID = "0b6f1d2e-aaaa-bbbb-cccc-111122223333";
    private static final Holder HOLDER = new Holder(null, "Jane Doe", "jane@example.com");

    @Nested
    @DisplayName("applied")
    class Applied {

        @Test
        void applied_requestedRevocation_carriesTheReasonTheOriginAndTheHolder() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.applied(ISSUANCE_ID, Origin.REQUEST, "key compromised", HOLDER);

            // Assert
            assertEquals(AuditEventType.REVOCATION, entry.type());
            assertEquals(AuditResult.SUCCESS, entry.result());
            assertEquals("issuance:" + ISSUANCE_ID, entry.resource());
            assertEquals("Request", entry.details().get("revocation_origin"));
            assertEquals("key compromised", entry.details().get("revocation_reason"));
            assertEquals(Map.of("name", "Jane Doe", "email", "jane@example.com"), entry.details().get("holder"));
        }

        @Test
        void applied_revocationCausedByTheWallet_omitsTheReason() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.applied(
                    ISSUANCE_ID, Origin.WALLET_NOTIFICATION, "ignored text", HOLDER);

            // Assert
            assertEquals("WalletNotification", entry.details().get("revocation_origin"));
            assertFalse(entry.details().containsKey("revocation_reason"));
        }

        @ParameterizedTest
        @NullSource
        @ValueSource(strings = {"", "   ", "\n\t"})
        void applied_requestedRevocationWithoutReason_carriesTheNotProvidedSentinel(String reason) {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.applied(ISSUANCE_ID, Origin.REQUEST, reason, HOLDER);

            // Assert
            assertThat(entry.details())
                    .containsEntry("revocation_origin", "Request")
                    .containsEntry("revocation_reason", RevocationAuditEvents.REASON_NOT_PROVIDED);
        }

        @Test
        void applied_revocationCausedByTheWalletWithoutReason_stillOmitsTheReason() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.applied(ISSUANCE_ID, Origin.WALLET_NOTIFICATION, null, HOLDER);

            // Assert
            assertThat(entry.details()).doesNotContainKey("revocation_reason");
        }

        @Test
        void applied_reasonLongerThanTheLimit_isTruncatedToTwoHundredEightyCharacters() {
            // Arrange
            String longReason = "x".repeat(400);

            // Act
            AuditEntry entry = RevocationAuditEvents.applied(ISSUANCE_ID, Origin.REQUEST, longReason, HOLDER);

            // Assert
            assertEquals(280, ((String) entry.details().get("revocation_reason")).length());
        }

        @Test
        void applied_reasonCutInTheMiddleOfAnEmoji_keepsTheSurrogatePairWhole() {
            // Arrange: 279 letters and an emoji (two UTF-16 units, one code point) make exactly 280 code points
            String reason = "x".repeat(279) + "\uD83D\uDE00" + "tail";

            // Act
            AuditEntry entry = RevocationAuditEvents.applied(ISSUANCE_ID, Origin.REQUEST, reason, HOLDER);

            // Assert
            String stored = (String) entry.details().get("revocation_reason");
            assertEquals(280, stored.codePointCount(0, stored.length()));
            assertTrue(stored.endsWith("\uD83D\uDE00"));
        }

        @Test
        void applied_reasonWithControlCharacters_replacesThemWithSpaces() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.applied(ISSUANCE_ID, Origin.REQUEST, "line1\nline2\ttab", HOLDER);

            // Assert
            assertEquals("line1 line2 tab", entry.details().get("revocation_reason"));
        }

        @Test
        void applied_reasonWithAJwtShapedValue_replacesItSoTheStarterDoesNotRejectTheEvent() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.applied(ISSUANCE_ID, Origin.REQUEST,
                    "see eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl please", HOLDER);

            // Assert
            assertEquals("see [redacted] please", entry.details().get("revocation_reason"));
        }
    }

    @Nested
    @DisplayName("refused")
    class Refused {

        @Test
        void refused_processNotFound_isDeniedWithoutHolderButWithTheRequestedReason() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.refused(
                    ISSUANCE_ID, Origin.REQUEST, "IssuanceNotFound", "key compromised", null);

            // Assert
            assertEquals(AuditResult.DENIED, entry.result());
            assertEquals("IssuanceNotFound", entry.reason());
            assertEquals("key compromised", entry.details().get("revocation_reason"));
            assertFalse(entry.details().containsKey("holder"));
        }

        @Test
        void refused_requestedRevocationWithoutReason_carriesTheNotProvidedSentinel() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.refused(
                    ISSUANCE_ID, Origin.REQUEST, "AlreadyRevoked", null, HOLDER);

            // Assert
            assertThat(entry.details()).containsEntry("revocation_reason", RevocationAuditEvents.REASON_NOT_PROVIDED);
        }

        @Test
        void refused_alreadyRevoked_isDeniedWithTheHolder() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.refused(
                    ISSUANCE_ID, Origin.REQUEST, "AlreadyRevoked", "again", HOLDER);

            // Assert
            assertEquals(AuditResult.DENIED, entry.result());
            assertEquals(Map.of("name", "Jane Doe", "email", "jane@example.com"), entry.details().get("holder"));
        }

        @Test
        void refused_statusListUnavailable_isFailure() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.refused(
                    ISSUANCE_ID, Origin.WALLET_NOTIFICATION, "StatusListUnavailable", null, HOLDER);

            // Assert
            assertEquals(AuditResult.FAILURE, entry.result());
            assertNull(entry.details().get("revocation_reason"));
        }
    }
}
