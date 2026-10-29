package es.in2.issuer.backend.shared.infrastructure.service;

import com.eudistack.auditoria.application.ReactiveAuditPublisher;
import com.eudistack.auditoria.context.ReactorAuditContexts;
import com.eudistack.auditoria.domain.AuditActor;
import com.eudistack.auditoria.domain.AuditContext;
import com.eudistack.auditoria.domain.AuditDraft;
import com.eudistack.auditoria.domain.AuditFact;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.ReactiveTransactionManager;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW;

/**
 * Hands the entries of the use cases to the audit outbox starter. {@code stage} joins the transaction that
 * is already active; the other staging methods open one of their own, since the starter never does (EC-09).
 */
@Slf4j
@Component
@ConditionalOnBooleanProperty("auditoria.publisher.enabled")
public class StarterAuditTrailAdapter implements AuditTrailPort {

    private final ReactiveAuditPublisher publisher;
    private final TransactionalOperator ownTransaction;

    public StarterAuditTrailAdapter(ReactiveAuditPublisher publisher, ReactiveTransactionManager transactionManager) {
        this.publisher = publisher;
        this.ownTransaction = TransactionalOperator.create(
                transactionManager, new DefaultTransactionDefinition(PROPAGATION_REQUIRES_NEW));
    }

    @Override
    public Mono<Void> stage(AuditEntry entry) {
        return Mono.defer(() -> publisher.stage(draftOf(entry)))
                .doOnError(error -> reportFailure(entry, error));
    }

    @Override
    public Mono<Void> stageInNewTransaction(AuditEntry entry) {
        return Mono.defer(() -> ownTransaction.transactional(publisher.stage(draftOf(entry))))
                .doOnError(error -> reportFailure(entry, error));
    }

    @Override
    public <T> Mono<T> withCorrelationId(String correlationId, Mono<T> flow) {
        return flow.contextWrite(ReactorAuditContexts.withCorrelationId(correlationId));
    }

    @Override
    public <T> Mono<T> asSystem(String tenant, String actorId, Mono<T> flow) {
        return flow.contextWrite(ReactorAuditContexts.system(tenant, actorId));
    }

    @Override
    public <T> Mono<T> asSystem(String actorId, Mono<T> flow) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            return tenant.isBlank() ? flow : asSystem(tenant, actorId, flow);
        });
    }

    @Override
    public <T> Mono<T> asHolder(String issuanceId, Mono<T> flow) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            if (tenant.isBlank()) {
                return flow;
            }
            AuditContext holderContext = new AuditContext(tenant, null, issuanceId, AuditActor.holder(issuanceId));
            return flow.contextWrite(ReactorAuditContexts.with(holderContext));
        });
    }

    private static AuditDraft draftOf(AuditEntry entry) {
        AuditFact fact = AuditFact.builder(entry.type().catalogName())
                .action(entry.type().action())
                .resource(entry.resource())
                .details(entry.details())
                .source(entry.source())
                .build();
        return switch (entry.result()) {
            case SUCCESS -> AuditDraft.success(fact);
            case DENIED -> AuditDraft.denied(fact, entry.reason());
            case FAILURE -> AuditDraft.failure(fact, entry.reason());
        };
    }

    /** Only the type and the kind of error are logged: the entry carries personal data. */
    private static void reportFailure(AuditEntry entry, Throwable error) {
        log.warn("action=stageAuditEvent status=failed eventType={} error={}",
                entry.type().catalogName(), error.getClass().getSimpleName());
    }
}
