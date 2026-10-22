package es.in2.issuer.backend.shared.infrastructure.service;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Stand-in for the audit trail until the audit outbox starter is available: it records nothing and
 * runs every flow untouched, so wiring the use cases to the port changes no behaviour. The adapter that
 * stages entries in the outbox replaces it.
 */
@Component
public class NoOpAuditTrailAdapter implements AuditTrailPort {

    @Override
    public Mono<Void> stage(AuditEntry entry) {
        return Mono.empty();
    }

    @Override
    public Mono<Void> stageInNewTransaction(AuditEntry entry) {
        return Mono.empty();
    }

    @Override
    public <T> Mono<T> withCorrelationId(String correlationId, Mono<T> flow) {
        return flow;
    }

    @Override
    public <T> Mono<T> asSystem(String tenant, String actorId, Mono<T> flow) {
        return flow;
    }
}
