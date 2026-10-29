package es.in2.issuer.backend.statuslist.domain.audit;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Holder;
import es.in2.issuer.backend.statuslist.domain.audit.RevocationAuditEvents.Origin;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        void applied_reasonWithControlCharacters_replacesThemWithSpaces() {
            // Arrange & Act
            AuditEntry entry = RevocationAuditEvents.applied(ISSUANCE_ID, Origin.REQUEST, "line1\nline2\ttab", HOLDER);

            // Assert
            assertEquals("line1 line2 tab", entry.details().get("revocation_reason"));
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
