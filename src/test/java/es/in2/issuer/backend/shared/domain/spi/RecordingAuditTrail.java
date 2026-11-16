package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

/**
 * Test double of {@link AuditTrailPort} that keeps what each flow staged, in order, and in which way,
 * so a test can assert on the entries without a database.
 */
public class RecordingAuditTrail implements AuditTrailPort {

    private final List<AuditEntry> staged = new ArrayList<>();
    private final List<AuditEntry> stagedInNewTransaction = new ArrayList<>();
    private final List<String> correlationIds = new ArrayList<>();
    private final List<String> systemScopes = new ArrayList<>();
    private final List<String> holderScopes = new ArrayList<>();
    private boolean failOnNewTransaction;
    private boolean failOnStage;
    private boolean requireContext;

    private static final String SCOPE_KEY = "recordingAuditTrail.scope";

    public RecordingAuditTrail failingOnStage() {
        this.failOnStage = true;
        return this;
    }

    /**
     * Makes every {@code stage} fail, as the starter does, when no audit scope ({@code asSystem} or
     * {@code asHolder}) is open around it. The request filter that opens the scope of a web request is not
     * part of this double, so a test that wants it must open the scope itself.
     */
    public RecordingAuditTrail requiringContext() {
        this.requireContext = true;
        return this;
    }

    private Mono<Void> record(List<AuditEntry> target, AuditEntry entry) {
        return Mono.deferContextual(ctx -> requireContext && !ctx.hasKey(SCOPE_KEY)
                ? Mono.error(new IllegalStateException("NO_CONTEXT"))
                : Mono.fromRunnable(() -> target.add(entry)));
    }

    public RecordingAuditTrail failingOnNewTransaction() {
        this.failOnNewTransaction = true;
        return this;
    }

    @Override
    public Mono<Void> stage(AuditEntry entry) {
        if (failOnStage) {
            return Mono.error(new IllegalStateException("outbox unavailable"));
        }
        return record(staged, entry);
    }

    @Override
    public Mono<Void> stageInNewTransaction(AuditEntry entry) {
        if (failOnNewTransaction) {
            return Mono.error(new IllegalStateException("outbox unavailable"));
        }
        return record(stagedInNewTransaction, entry);
    }

    @Override
    public <T> Mono<T> withCorrelationId(String correlationId, Mono<T> flow) {
        return Mono.fromRunnable(() -> correlationIds.add(correlationId)).then(flow);
    }

    @Override
    public <T> Mono<T> asSystem(String actorId, Mono<T> flow) {
        return Mono.defer(() -> {
            systemScopes.add(actorId);
            return flow.contextWrite(ctx -> ctx.put(SCOPE_KEY, true));
        });
    }

    @Override
    public <T> Mono<T> asHolder(String issuanceId, Mono<T> flow) {
        return Mono.defer(() -> {
            holderScopes.add(issuanceId);
            correlationIds.add(issuanceId);
            return flow.contextWrite(ctx -> ctx.put(SCOPE_KEY, true));
        });
    }

    public List<String> holderScopes() {
        return holderScopes;
    }

    @Override
    public <T> Mono<T> asSystem(String tenant, String actorId, Mono<T> flow) {
        return Mono.fromRunnable(() -> systemScopes.add(tenant + "/" + actorId))
                .then(flow)
                .contextWrite(ctx -> ctx.put(SCOPE_KEY, true));
    }

    /** The {@code tenant/actor} of every background scope opened, in order. */
    public List<String> systemScopes() {
        return List.copyOf(systemScopes);
    }

    public List<AuditEntry> staged() {
        return List.copyOf(staged);
    }

    public List<AuditEntry> stagedInNewTransaction() {
        return List.copyOf(stagedInNewTransaction);
    }

    public List<AuditEntry> all() {
        List<AuditEntry> all = new ArrayList<>(staged);
        all.addAll(stagedInNewTransaction);
        return all;
    }

    public List<String> correlationIds() {
        return List.copyOf(correlationIds);
    }
}
