package es.in2.issuer.backend.shared.infrastructure.service;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The audit trail while {@code auditoria.publisher.enabled} is off: it records nothing and runs every flow
 * untouched, so wiring the use cases to the port changes no behaviour.
 */
@Component
@ConditionalOnBooleanProperty(name = "auditoria.publisher.enabled", havingValue = false, matchIfMissing = true)
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

    @Override
    public <T> Mono<T> asSystem(String actorId, Mono<T> flow) {
        return flow;
    }

    @Override
    public <T> Mono<T> asHolder(String issuanceId, Mono<T> flow) {
        return flow;
    }
}
