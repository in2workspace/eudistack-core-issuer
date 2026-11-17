package es.in2.issuer.backend.shared.domain.model.audit;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuditEventTypeTest {

    @Test
    void resultFor_reasonOfTheDeniedVocabulary_returnsDenied() {
        // Arrange
        AuditEventType type = AuditEventType.AUTHORIZATION_DECISION;

        // Act
        Optional<AuditResult> result = type.resultFor("TenantMismatch");

        // Assert
        assertEquals(Optional.of(AuditResult.DENIED), result);
    }

    @Test
    void resultFor_reasonOfTheFailureVocabulary_returnsFailure() {
        // Arrange
        AuditEventType type = AuditEventType.EXTERNAL_SYSTEM_ACCESS;

        // Act
        Optional<AuditResult> result = type.resultFor("Timeout");

        // Assert
        assertEquals(Optional.of(AuditResult.FAILURE), result);
    }

    @Test
    void resultFor_reasonOfAnotherType_returnsEmpty() {
        // Arrange
        AuditEventType type = AuditEventType.ISSUANCE_WITHDRAWN;

        // Act
        Optional<AuditResult> result = type.resultFor("MailDeliveryFailed");

        // Assert
        assertEquals(Optional.empty(), result);
    }

    @Test
    void resultFor_reasonThatMeansDifferentResultsInOtherTypes_followsTheTypeVocabulary() {
        // Arrange
        AuditEventType revocation = AuditEventType.REVOCATION;
        AuditEventType attemptFailed = AuditEventType.ISSUANCE_ATTEMPT_FAILED;

        // Act
        Optional<AuditResult> inRevocation = revocation.resultFor("StatusListUnavailable");
        Optional<AuditResult> inAttemptFailed = attemptFailed.resultFor("PolicyDenied");

        // Assert
        assertEquals(Optional.of(AuditResult.FAILURE), inRevocation);
        assertEquals(Optional.of(AuditResult.DENIED), inAttemptFailed);
    }

    @Test
    void action_ofEachTypeInTheIssuerBatch_matchesTheCatalogue() {
        // Arrange & Act & Assert
        assertEquals("Authorize", AuditEventType.AUTHORIZATION_DECISION.action());
        assertEquals("Issue", AuditEventType.ISSUANCE_COMPLETED.action());
        assertEquals("SendOffer", AuditEventType.CREDENTIAL_OFFER_SENT.action());
        assertEquals("Revoke", AuditEventType.REVOCATION.action());
        assertEquals("AccessExternalSystem", AuditEventType.EXTERNAL_SYSTEM_ACCESS.action());
        assertEquals("Sign", AuditEventType.SIGNATURE_REQUESTED.action());
    }
}
