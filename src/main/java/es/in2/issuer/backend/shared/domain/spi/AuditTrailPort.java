package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.function.Function;

/**
 * Output port to the audit trail (EUD-244): the use case states what happened and the adapter hands it
 * to the audit outbox. The domain depends only on this interface, never on the outbox starter.
 *
 * <p>The tenant, actor, organization and correlation id are read from the audit context of the
 * operation, not passed here.
 */
public interface AuditTrailPort {

    /**
     * Stages the entry in the transaction that is already active, so it commits or rolls back together
     * with the business write it describes. Fails when no transaction is active.
     */
    Mono<Void> stage(AuditEntry entry);

    /**
     * Stages the entry in a short transaction of its own, for facts that have no business write to
     * join: a refusal after the business transaction rolled back, a read, or a call to a third party.
     */
    Mono<Void> stageInNewTransaction(AuditEntry entry);

    /**
     * Stages the entry in a transaction of its own and never fails the caller: for a fact that already
     * happened outside any business write (a mail sent, an offer delivered), where a broken audit
     * channel must not undo or hide the operation. The adapter reports the failure itself.
     */
    default Mono<Void> stageBestEffort(AuditEntry entry) {
        return stageInNewTransaction(entry).onErrorResume(auditError -> Mono.empty());
    }

    /** Runs {@code flow} with the given correlation id, which replaces the one of the request. */
    <T> Mono<T> withCorrelationId(String correlationId, Mono<T> flow);

    /** Runs {@code flow} with the audit context of a background process acting on {@code tenant}. */
    <T> Mono<T> asSystem(String tenant, String actorId, Mono<T> flow);

    /**
     * Lets {@code flow} fail as it would anyway and, before the error propagates, stages the entry the
     * classifier derives from it in a transaction of its own. An error without an audit entry (no
     * catalogue reason for it) propagates untouched. A failure to stage never hides the original error.
     */
    default <T> Mono<T> stageOnError(Mono<T> flow, Function<Throwable, Optional<AuditEntry>> classifier) {
        return flow.onErrorResume(error -> classifier.apply(error)
                .map(entry -> stageBestEffort(entry).then(Mono.<T>error(error)))
                .orElseGet(() -> Mono.error(error)));
    }
}
