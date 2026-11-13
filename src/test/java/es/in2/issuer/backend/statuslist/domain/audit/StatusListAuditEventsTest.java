package es.in2.issuer.backend.statuslist.domain.audit;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.audit.AuditSource;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class StatusListAuditEventsTest {

    private static final String ISSUANCE_ID = "0b6f1d2e-aaaa-bbbb-cccc-111122223333";
    private static final String LIST_URI = "https://issuer.example.com/backoffice/v1/credentials/status/1";

    @Test
    void listCreated_tokenList_reportsTheTokenFormatTheUriAndTheSize() {
        // Arrange & Act
        AuditEntry entry = StatusListAuditEvents.listCreated(1L, LIST_URI, StatusListFormat.TOKEN_JWT, 131_072);

        // Assert
        assertEquals(AuditEventType.STATUS_LIST_CREATED, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals(AuditSource.STATUS_LISTS, entry.source());
        assertEquals("status-list:1", entry.resource());
        assertEquals(LIST_URI, entry.details().get("list_uri"));
        assertEquals("TokenStatusList", entry.details().get("format"));
        assertEquals(131_072, entry.details().get("size"));
    }

    @Test
    void listCreated_bitstringList_reportsTheBitstringFormat() {
        // Arrange & Act
        AuditEntry entry = StatusListAuditEvents.listCreated(2L, LIST_URI, StatusListFormat.BITSTRING_VC, 131_072);

        // Assert
        assertEquals("BitstringStatusList", entry.details().get("format"));
    }

    @Test
    void listCreationFailed_isFailureSigningFailedKeepingTheRequiredDetails() {
        // Arrange & Act
        AuditEntry entry = StatusListAuditEvents.listCreationFailed(3L, LIST_URI, StatusListFormat.BITSTRING_VC, 131_072);

        // Assert
        assertEquals(AuditResult.FAILURE, entry.result());
        assertEquals("SigningFailed", entry.reason());
        assertEquals(LIST_URI, entry.details().get("list_uri"));
    }

    @Test
    void reserved_carriesTheUriAndTheIndexOfThePosition() {
        // Arrange & Act
        AuditEntry entry = StatusListAuditEvents.reserved(ISSUANCE_ID, LIST_URI, 42);

        // Assert
        assertEquals(AuditEventType.STATUS_ENTRY_CHANGED, entry.type());
        assertEquals(AuditSource.STATUS_LISTS, entry.source());
        assertEquals("status-list-entry:" + ISSUANCE_ID, entry.resource());
        assertEquals("Reserve", entry.details().get("operation"));
        assertEquals(LIST_URI, entry.details().get("list_uri"));
        assertEquals(42, entry.details().get("list_index"));
    }

    @Test
    void revoked_carriesTheRevokeOperationWithTheUriAndTheIndex() {
        // Arrange & Act
        AuditEntry entry = StatusListAuditEvents.revoked(ISSUANCE_ID, LIST_URI, 7);

        // Assert
        assertEquals("Revoke", entry.details().get("operation"));
        assertEquals(7, entry.details().get("list_index"));
    }

    @Test
    void reservationFailed_omitsTheUriAndTheIndexBecauseNoPositionWasReserved() {
        // Arrange & Act
        AuditEntry entry = StatusListAuditEvents.reservationFailed(ISSUANCE_ID, "ListFull");

        // Assert
        assertEquals(AuditResult.FAILURE, entry.result());
        assertEquals("ListFull", entry.reason());
        assertEquals("Reserve", entry.details().get("operation"));
        assertFalse(entry.details().containsKey("list_uri"));
        assertFalse(entry.details().containsKey("list_index"));
    }

    @Test
    void revocationFailed_isFailureStatusListUnavailable() {
        // Arrange & Act
        AuditEntry entry = StatusListAuditEvents.revocationFailed(ISSUANCE_ID, "StatusListUnavailable");

        // Assert
        assertEquals("Revoke", entry.details().get("operation"));
        assertEquals("StatusListUnavailable", entry.reason());
    }

    @Test
    void published_listSignedAgain_isSuccessWithTheUriAndTheHash() {
        // Arrange & Act
        AuditEntry entry = StatusListAuditEvents.published(7L, "https://issuer.example/status/7", "sha256:abc");

        // Assert
        assertEquals(AuditEventType.STATUS_LIST_PUBLISHED, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("status-list:7", entry.resource());
        assertEquals("sha256:abc", entry.details().get("list_hash"));
    }

    @Test
    void publicationFailed_signingFailed_isFailureWithoutAHash() {
        // Arrange & Act
        AuditEntry entry = StatusListAuditEvents.publicationFailed(7L, "https://issuer.example/status/7", "SigningFailed");

        // Assert
        assertEquals(AuditResult.FAILURE, entry.result());
        assertEquals("SigningFailed", entry.reason());
        assertFalse(entry.details().containsKey("list_hash"));
    }
}
