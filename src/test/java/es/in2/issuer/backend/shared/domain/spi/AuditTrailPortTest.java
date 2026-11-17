package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditTrailPortTest {

    private static final AuditEntry REJECTION =
            AuditEntry.denied(AuditEventType.REVOCATION, "issuance:1", "AlreadyRevoked", Map.of());

    @Test
    void stageBestEffort_stagingSucceeds_stagesTheEntryInANewTransaction() {
        // Arrange
        RecordingAuditTrail trail = new RecordingAuditTrail();

        // Act
        Mono<Void> staged = trail.stageBestEffort(REJECTION);

        // Assert
        StepVerifier.create(staged).verifyComplete();
        assertEquals(1, trail.stagedInNewTransaction().size());
    }

    @Test
    void stageBestEffort_stagingFails_completesWithoutError() {
        // Arrange
        RecordingAuditTrail trail = new RecordingAuditTrail().failingOnNewTransaction();

        // Act
        Mono<Void> staged = trail.stageBestEffort(REJECTION);

        // Assert
        StepVerifier.create(staged).verifyComplete();
    }

    @Test
    void stageOnError_flowFailsWithClassifiedError_stagesTheEntryAndKeepsTheOriginalError() {
        // Arrange
        RecordingAuditTrail trail = new RecordingAuditTrail();
        IllegalArgumentException original = new IllegalArgumentException("already revoked");
        Mono<String> flow = Mono.error(original);

        // Act
        Mono<String> audited = trail.stageOnError(flow, error -> Optional.of(REJECTION));

        // Assert
        StepVerifier.create(audited).expectErrorMatches(error -> error == original).verify();
        assertEquals(1, trail.stagedInNewTransaction().size());
        assertEquals("AlreadyRevoked", trail.stagedInNewTransaction().getFirst().reason());
    }

    @Test
    void stageOnError_flowFailsWithErrorWithoutEntry_propagatesWithoutStaging() {
        // Arrange
        RecordingAuditTrail trail = new RecordingAuditTrail();
        IllegalStateException original = new IllegalStateException("not in the catalogue");
        Mono<String> flow = Mono.error(original);

        // Act
        Mono<String> audited = trail.stageOnError(flow, error -> Optional.empty());

        // Assert
        StepVerifier.create(audited).expectErrorMatches(error -> error == original).verify();
        assertTrue(trail.all().isEmpty());
    }

    @Test
    void stageOnError_flowSucceeds_returnsTheValueAndStagesNothing() {
        // Arrange
        RecordingAuditTrail trail = new RecordingAuditTrail();

        // Act
        Mono<String> audited = trail.stageOnError(Mono.just("ok"), error -> Optional.of(REJECTION));

        // Assert
        StepVerifier.create(audited).expectNext("ok").verifyComplete();
        assertTrue(trail.all().isEmpty());
    }

    @Test
    void stageOnError_stagingItselfFails_stillPropagatesTheOriginalError() {
        // Arrange
        RecordingAuditTrail trail = new RecordingAuditTrail().failingOnNewTransaction();
        IllegalArgumentException original = new IllegalArgumentException("already revoked");

        // Act
        Mono<String> audited = trail.stageOnError(Mono.error(original), error -> Optional.of(REJECTION));

        // Assert
        StepVerifier.create(audited).expectErrorMatches(error -> error == original).verify();
    }
}
