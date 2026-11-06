package es.in2.issuer.backend.shared.domain.model.audit;

import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Holder;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.OfferKind;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class IssuanceAuditEventsTest {

    private static final String ISSUANCE_ID = "0b6f1d2e-aaaa-bbbb-cccc-111122223333";
    private static final Instant EXPIRES_AT = Instant.parse("2026-10-21T10:10:00Z");
    private static final Holder HOLDER = new Holder(null, "Jane Doe", "jane@example.com");

    @Nested
    @DisplayName("deliveryMethodOf")
    class DeliveryMethod {

        @Test
        void deliveryMethodOf_emailOnly_returnsEmail() {
            // Arrange & Act
            String method = IssuanceAuditEvents.deliveryMethodOf("email");

            // Assert
            assertEquals("email", method);
        }

        @Test
        void deliveryMethodOf_emailAndUi_returnsEmail() {
            // Arrange & Act
            String method = IssuanceAuditEvents.deliveryMethodOf("ui,email");

            // Assert
            assertEquals("email", method);
        }

        @Test
        void deliveryMethodOf_uiAndDirect_returnsUi() {
            // Arrange & Act
            String method = IssuanceAuditEvents.deliveryMethodOf("direct,ui");

            // Assert
            assertEquals("ui", method);
        }

        @Test
        void deliveryMethodOf_directOnly_returnsDirect() {
            // Arrange & Act
            String method = IssuanceAuditEvents.deliveryMethodOf("direct");

            // Assert
            assertEquals("direct", method);
        }
    }

    @Nested
    @DisplayName("requested")
    class Requested {

        @Test
        void requested_emailDelivery_carriesTheDetailsOfTheCatalogue() {
            // Arrange & Act
            AuditEntry entry = IssuanceAuditEvents.requested(
                    ISSUANCE_ID, "learcredential.employee", "email", HOLDER, EXPIRES_AT);

            // Assert
            assertEquals(AuditEventType.ISSUANCE_REQUESTED, entry.type());
            assertEquals(AuditResult.SUCCESS, entry.result());
            assertEquals("issuance:" + ISSUANCE_ID, entry.resource());
            assertEquals("learcredential.employee", entry.details().get("attestation_type"));
            assertEquals("ThirdParty", entry.details().get("issuance_mode"));
            assertEquals("email", entry.details().get("delivery_method"));
            assertEquals(EXPIRES_AT, entry.details().get("offer_expires_at"));
            assertEquals(Map.of("name", "Jane Doe", "email", "jane@example.com"), entry.details().get("holder"));
        }

        @Test
        void requested_directDelivery_omitsTheOfferExpiry() {
            // Arrange & Act
            AuditEntry entry = IssuanceAuditEvents.requested(
                    ISSUANCE_ID, "learcredential.employee", "direct", HOLDER, EXPIRES_AT);

            // Assert
            assertFalse(entry.details().containsKey("offer_expires_at"));
        }

        @Test
        void requested_holderWithoutIdentifier_omitsTheIdentifierInsteadOfInventingIt() {
            // Arrange & Act
            AuditEntry entry = IssuanceAuditEvents.requested(
                    ISSUANCE_ID, "learcredential.employee", "ui", HOLDER, EXPIRES_AT);

            // Assert
            Map<?, ?> holder = (Map<?, ?>) entry.details().get("holder");
            assertFalse(holder.containsKey("identifier"));
        }
    }

    @Nested
    @DisplayName("notificationReceived")
    class NotificationReceived {

        @Test
        void notificationReceived_noRevocation_reportsNoResultingAction() {
            // Arrange & Act
            AuditEntry entry = IssuanceAuditEvents.notificationReceived(ISSUANCE_ID, "credential_accepted", false);

            // Assert
            assertEquals(AuditEventType.WALLET_NOTIFICATION_RECEIVED, entry.type());
            assertEquals(AuditResult.SUCCESS, entry.result());
            assertEquals("credential_accepted", entry.details().get("notification_event"));
            assertEquals("None", entry.details().get("resulting_action"));
        }

        @Test
        void notificationReceived_revocationApplied_reportsRevoked() {
            // Arrange & Act
            AuditEntry entry = IssuanceAuditEvents.notificationReceived(ISSUANCE_ID, "credential_deleted", true);

            // Assert
            assertEquals("Revoked", entry.details().get("resulting_action"));
        }
    }

    @Nested
    @DisplayName("offerSent")
    class OfferSent {

        @Test
        void offerSent_mailDelivered_isSuccessWithTheOfferDetails() {
            // Arrange & Act
            AuditEntry entry = IssuanceAuditEvents.offerSent(
                    ISSUANCE_ID, OfferKind.INITIAL, "jane@example.com", EXPIRES_AT, true);

            // Assert
            assertEquals(AuditEventType.CREDENTIAL_OFFER_SENT, entry.type());
            assertEquals(AuditResult.SUCCESS, entry.result());
            assertNull(entry.reason());
            assertEquals("Initial", entry.details().get("offer_kind"));
            assertEquals("jane@example.com", entry.details().get("recipient_email"));
            assertEquals(EXPIRES_AT, entry.details().get("offer_expires_at"));
        }

        @Test
        void offerSent_reissuedOfferNotDelivered_isFailureWithMailDeliveryFailed() {
            // Arrange & Act
            AuditEntry entry = IssuanceAuditEvents.offerSent(
                    ISSUANCE_ID, OfferKind.REISSUED, "jane@example.com", EXPIRES_AT, false);

            // Assert
            assertEquals(AuditResult.FAILURE, entry.result());
            assertEquals("MailDeliveryFailed", entry.reason());
            assertEquals("Reissued", entry.details().get("offer_kind"));
        }
    }

    @Nested
    @DisplayName("queried")
    class Queried {

        @Test
        void queried_withoutAnOrganization_namesTheTenantAsTheScope() {
            // Arrange & Act
            AuditEntry entry = IssuanceAuditEvents.queried(null, 3);

            // Assert
            assertEquals("issuance-list:tenant", entry.resource());
            assertEquals(3, entry.details().get("returned_count"));
        }
    }
}
