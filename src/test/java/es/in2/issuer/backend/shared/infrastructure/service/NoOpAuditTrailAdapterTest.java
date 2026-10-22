package es.in2.issuer.backend.shared.infrastructure.service;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

class NoOpAuditTrailAdapterTest {

    private final NoOpAuditTrailAdapter adapter = new NoOpAuditTrailAdapter();
    private final AuditEntry entry = AuditEntry.success(AuditEventType.ISSUANCE_REQUESTED, "issuance:1", Map.of());

    @Test
    void stage_anyEntry_completesWithoutEffect() {
        // Arrange & Act
        Mono<Void> staged = adapter.stage(entry);

        // Assert
        StepVerifier.create(staged).verifyComplete();
    }

    @Test
    void stageInNewTransaction_anyEntry_completesWithoutEffect() {
        // Arrange & Act
        Mono<Void> staged = adapter.stageInNewTransaction(entry);

        // Assert
        StepVerifier.create(staged).verifyComplete();
    }

    @Test
    void withCorrelationId_aFlow_returnsTheSameFlowUntouched() {
        // Arrange
        Mono<String> flow = Mono.just("result");

        // Act
        Mono<String> scoped = adapter.withCorrelationId("process-1", flow);

        // Assert
        StepVerifier.create(scoped).expectNext("result").verifyComplete();
    }

    @Test
    void asSystem_aFlow_returnsTheSameFlowUntouched() {
        // Arrange
        Mono<String> flow = Mono.just("result");

        // Act
        Mono<String> scoped = adapter.asSystem("sandbox", "issuer", flow);

        // Assert
        StepVerifier.create(scoped).expectNext("result").verifyComplete();
    }
}
