package es.in2.issuer.backend.shared.domain.model.audit;

import es.in2.issuer.backend.shared.domain.exception.InvalidAuditEntryException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditEntryTest {

    private static final String RESOURCE = "issuance:0b6f1d2e";

    @Nested
    @DisplayName("success")
    class Success {

        @Test
        void success_withoutDetails_buildsEntryWithTypeSourceAndNoReason() {
            // Arrange
            AuditEventType type = AuditEventType.ISSUANCE_REQUESTED;

            // Act
            AuditEntry entry = AuditEntry.success(type, RESOURCE, null);

            // Assert
            assertEquals(type, entry.type());
            assertEquals(AuditSource.ISSUER, entry.source());
            assertEquals(AuditResult.SUCCESS, entry.result());
            assertNull(entry.reason());
            assertTrue(entry.details().isEmpty());
        }

        @Test
        void success_withReason_throwsInvalidAuditEntryException() {
            // Arrange
            AuditEventType type = AuditEventType.REVOCATION;

            // Act & Assert
            assertThrows(InvalidAuditEntryException.class,
                    () -> new AuditEntry(type, null, RESOURCE, AuditResult.SUCCESS, "PolicyDenied", Map.of()));
        }
    }

    @Nested
    @DisplayName("denied and failure")
    class DeniedAndFailure {

        @Test
        void denied_withReasonOfTheType_buildsDeniedEntry() {
            // Arrange
            AuditEventType type = AuditEventType.REVOCATION;

            // Act
            AuditEntry entry = AuditEntry.denied(type, RESOURCE, "AlreadyRevoked", Map.of());

            // Assert
            assertEquals(AuditResult.DENIED, entry.result());
            assertEquals("AlreadyRevoked", entry.reason());
        }

        @Test
        void failure_withReasonOfTheType_buildsFailureEntry() {
            // Arrange
            AuditEventType type = AuditEventType.CREDENTIAL_OFFER_SENT;

            // Act
            AuditEntry entry = AuditEntry.failure(type, RESOURCE, "MailDeliveryFailed", Map.of());

            // Assert
            assertEquals(AuditResult.FAILURE, entry.result());
        }

        @Test
        void denied_withoutReason_throwsInvalidAuditEntryException() {
            // Arrange
            AuditEventType type = AuditEventType.REVOCATION;

            // Act & Assert
            assertThrows(InvalidAuditEntryException.class, () -> AuditEntry.denied(type, RESOURCE, null, Map.of()));
        }

        @Test
        void denied_withReasonOutsideTheVocabulary_throwsInvalidAuditEntryException() {
            // Arrange
            AuditEventType type = AuditEventType.REVOCATION;

            // Act & Assert
            assertThrows(InvalidAuditEntryException.class,
                    () -> AuditEntry.denied(type, RESOURCE, "credential.holder_cnf.invalid", Map.of()));
        }

        @Test
        void failure_withReasonThatDeterminesDenied_throwsInvalidAuditEntryException() {
            // Arrange
            AuditEventType type = AuditEventType.REVOCATION;

            // Act & Assert
            assertThrows(InvalidAuditEntryException.class,
                    () -> AuditEntry.failure(type, RESOURCE, "AlreadyRevoked", Map.of()));
        }
    }

    @Nested
    @DisplayName("forReason")
    class ForReason {

        @Test
        void forReason_reasonOfTheDeniedVocabulary_derivesDenied() {
            // Arrange
            AuditEventType type = AuditEventType.EXTERNAL_SYSTEM_ACCESS;

            // Act
            AuditEntry entry = AuditEntry.forReason(type, RESOURCE, "AuthenticationRejected", Map.of());

            // Assert
            assertEquals(AuditResult.DENIED, entry.result());
        }

        @Test
        void forReason_reasonOfTheFailureVocabulary_derivesFailure() {
            // Arrange
            AuditEventType type = AuditEventType.EXTERNAL_SYSTEM_ACCESS;

            // Act
            AuditEntry entry = AuditEntry.forReason(type, RESOURCE, "Timeout", Map.of());

            // Assert
            assertEquals(AuditResult.FAILURE, entry.result());
        }

        @Test
        void forReason_reasonOutsideTheVocabulary_throwsInvalidAuditEntryException() {
            // Arrange
            AuditEventType type = AuditEventType.EXTERNAL_SYSTEM_ACCESS;

            // Act & Assert
            assertThrows(InvalidAuditEntryException.class,
                    () -> AuditEntry.forReason(type, RESOURCE, "persistence_failed", Map.of()));
        }
    }

    @Nested
    @DisplayName("resource and source")
    class ResourceAndSource {

        @Test
        void constructor_withBlankResource_throwsInvalidAuditEntryException() {
            // Arrange
            AuditEventType type = AuditEventType.ISSUANCE_REQUESTED;

            // Act & Assert
            assertThrows(InvalidAuditEntryException.class, () -> AuditEntry.success(type, " ", Map.of()));
        }

        @Test
        void withSource_overridesTheDefaultSource() {
            // Arrange
            AuditEntry entry = AuditEntry.success(AuditEventType.EXTERNAL_SYSTEM_ACCESS, "external-system:qtsp", Map.of());

            // Act
            AuditEntry signing = entry.withSource(AuditSource.SIGNING);

            // Assert
            assertEquals(AuditSource.ISSUER, entry.source());
            assertEquals(AuditSource.SIGNING, signing.source());
        }

        @Test
        void success_ofStatusListType_defaultsToStatusListsSource() {
            // Arrange
            AuditEventType type = AuditEventType.STATUS_ENTRY_CHANGED;

            // Act
            AuditEntry entry = AuditEntry.success(type, "status-list:1", Map.of());

            // Assert
            assertEquals(AuditSource.STATUS_LISTS, entry.source());
        }
    }

    @Nested
    @DisplayName("details")
    class Details {

        @Test
        void success_withNullValues_omitsThemAtEveryLevel() {
            // Arrange
            Map<String, Object> holder = new HashMap<>();
            holder.put("identifier", "12345678Z");
            holder.put("email", null);
            Map<String, Object> details = new HashMap<>();
            details.put("holder", holder);
            details.put("valid_until", null);
            details.put("issued_attributes", List.of("name"));

            // Act
            AuditEntry entry = AuditEntry.success(AuditEventType.ISSUANCE_COMPLETED, RESOURCE, details);

            // Assert
            assertFalse(entry.details().containsKey("valid_until"));
            Map<?, ?> cleanedHolder = (Map<?, ?>) entry.details().get("holder");
            assertEquals(Map.of("identifier", "12345678Z"), cleanedHolder);
            assertEquals(List.of("name"), entry.details().get("issued_attributes"));
        }

        @Test
        void success_afterTheSourceMapIsChanged_keepsItsOwnCopy() {
            // Arrange
            Map<String, Object> details = new HashMap<>();
            details.put("returned_count", 3);
            AuditEntry entry = AuditEntry.success(AuditEventType.ISSUANCE_QUERIED, RESOURCE, details);

            // Act
            details.put("returned_count", 99);

            // Assert
            assertEquals(3, entry.details().get("returned_count"));
        }
    }
}
