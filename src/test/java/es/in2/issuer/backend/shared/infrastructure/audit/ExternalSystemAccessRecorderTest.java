package es.in2.issuer.backend.shared.infrastructure.audit;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.audit.AuditSource;
import es.in2.issuer.backend.shared.domain.model.audit.ExternalSystemTarget;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.SocketTimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExternalSystemAccessRecorderTest {

    private static final ExternalSystemTarget MAIL = ExternalSystemTarget.mailProvider("smtp.example.com", "Basic");

    private final RecordingAuditTrail trail = new RecordingAuditTrail();
    private final ExternalSystemAccessRecorder recorder = new ExternalSystemAccessRecorder(trail);

    @Test
    void record_callSucceeds_stagesSuccessWithTheCallDetailsAndReturnsTheValue() {
        // Arrange
        Mono<String> call = Mono.just("sent");

        // Act
        Mono<String> recorded = recorder.record(MAIL, "credential-offer-email", call);

        // Assert
        StepVerifier.create(recorded).expectNext("sent").verifyComplete();
        assertEquals(1, trail.stagedInNewTransaction().size());
        AuditEntry entry = trail.stagedInNewTransaction().getFirst();
        assertEquals(AuditEventType.EXTERNAL_SYSTEM_ACCESS, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals(AuditSource.ISSUER, entry.source());
        assertEquals("external-system:smtp.example.com", entry.resource());
        assertEquals("MailProvider", entry.details().get("system_type"));
        assertEquals("smtp.example.com", entry.details().get("system"));
        assertEquals("credential-offer-email", entry.details().get("operation"));
        assertEquals("Basic", entry.details().get("authentication_method"));
        assertTrue(entry.details().get("duration_ms") instanceof Long);
    }

    @Test
    void record_callCompletesWithoutValue_stagesSuccess() {
        // Arrange
        Mono<Void> call = Mono.empty();

        // Act
        Mono<Void> recorded = recorder.record(MAIL, "tx-code-email", call);

        // Assert
        StepVerifier.create(recorded).verifyComplete();
        assertEquals(AuditResult.SUCCESS, trail.stagedInNewTransaction().getFirst().result());
    }

    @Test
    void record_callTimesOut_stagesFailureWithTimeoutAndKeepsTheOriginalError() {
        // Arrange
        SocketTimeoutException original = new SocketTimeoutException("Read timed out");
        Mono<String> call = Mono.error(original);

        // Act
        Mono<String> recorded = recorder.record(MAIL, "credential-offer-email", call);

        // Assert
        StepVerifier.create(recorded).expectErrorMatches(error -> error == original).verify();
        AuditEntry entry = trail.stagedInNewTransaction().getFirst();
        assertEquals(AuditResult.FAILURE, entry.result());
        assertEquals("Timeout", entry.reason());
    }

    @Test
    void record_callOfTheSigningModule_stagesTheEventWithTheSigningSource() {
        // Arrange
        ExternalSystemTarget qtsp = ExternalSystemTarget.qtsp("qtsp.example.com", "OAuthClientCredentials");

        // Act
        Mono<String> recorded = recorder.record(qtsp, "signatures/signHash", Mono.just("signature"));

        // Assert
        StepVerifier.create(recorded).expectNext("signature").verifyComplete();
        AuditEntry entry = trail.stagedInNewTransaction().getFirst();
        assertEquals(AuditSource.SIGNING, entry.source());
        assertEquals("Qtsp", entry.details().get("system_type"));
    }

    @Test
    void record_stagingFails_stillReturnsTheValueOfTheCall() {
        // Arrange
        RecordingAuditTrail brokenTrail = new RecordingAuditTrail().failingOnNewTransaction();
        ExternalSystemAccessRecorder brokenRecorder = new ExternalSystemAccessRecorder(brokenTrail);

        // Act
        Mono<String> recorded = brokenRecorder.record(MAIL, "credential-offer-email", Mono.just("sent"));

        // Assert
        StepVerifier.create(recorded).expectNext("sent").verifyComplete();
    }

    @Test
    void record_stagingFailsAfterCallError_stillPropagatesTheCallError() {
        // Arrange
        RecordingAuditTrail brokenTrail = new RecordingAuditTrail().failingOnNewTransaction();
        ExternalSystemAccessRecorder brokenRecorder = new ExternalSystemAccessRecorder(brokenTrail);
        IllegalStateException original = new IllegalStateException("smtp down");

        // Act
        Mono<String> recorded = brokenRecorder.record(MAIL, "credential-offer-email", Mono.error(original));

        // Assert
        StepVerifier.create(recorded).expectErrorMatches(error -> error == original).verify();
    }
}
