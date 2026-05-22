package es.in2.issuer.backend.dome.infrastructure.observability;

import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Micrometer metrics for DOME key migration.
 * <p>
 * Registers the following meters at construction time:
 * <ul>
 *   <li>{@code dome_key_migration_duration_ms} — Timer for Plan-A/B end-to-end duration.</li>
 *   <li>{@code dome_key_migration_reissuance_total} — Counter with dynamic {@code outcome}
 *       and {@code reason} tags, registered per invocation to support cardinality-safe
 *       label combinations.</li>
 *   <li>{@code dome_key_migration_audit_completeness} — Gauge expressing the ratio of
 *       records that reached a terminal status with an audit evidence URI vs. total
 *       terminal-status records. Updated via atomic accumulators incremented by the
 *       audit adapter on each successful {@code recordPlanAOk} call.</li>
 *   <li>{@code dome_key_migration_hash_mismatches_total} — Counter for SHA-256 hash
 *       mismatches detected during re-issuance (ES-09).</li>
 * </ul>
 * </p>
 */
@Component
public class KeyMigrationMetrics {

    private final MeterRegistry registry;

    /**
     * Injected for future gauge queries at the repository level.
     * The current gauge uses in-process accumulators for low-overhead sampling.
     */
    private final KmsKeyMigrationRepositoryPort migrationRepositoryPort;

    // --- Plan-A/B duration timer (registered once, reused) ---
    private final Timer migrationTimer;

    // --- Hash-mismatch counter (registered once) ---
    private final Counter hashMismatchCounter;

    // --- Audit completeness accumulators (updated by CloudWatchKeyMigrationAuditAdapter) ---
    private final AtomicLong auditWithEvidence = new AtomicLong(0);
    private final AtomicLong auditTotalFinal = new AtomicLong(0);

    /**
     * Constructor wires up all static meters.
     * Lombok {@code @RequiredArgsConstructor} generates the 2-arg constructor
     * (registry + migrationRepositoryPort); we complement it via a Spring
     * {@code @Bean} init or post-construct if more wiring is needed.
     * <p>
     * Since Lombok is used with final fields, we must delegate to a regular
     * constructor that registers meters after injection.
     * </p>
     */
    public KeyMigrationMetrics(MeterRegistry registry,
                               KmsKeyMigrationRepositoryPort migrationRepositoryPort) {
        this.registry = registry;
        this.migrationRepositoryPort = migrationRepositoryPort;

        this.migrationTimer = Timer.builder("dome_key_migration_duration_ms")
                .description("Plan A/B end-to-end duration")
                .register(registry);

        this.hashMismatchCounter = Counter.builder("dome_key_migration_hash_mismatches_total")
                .description("SHA-256 hash mismatches detected during re-issuance (ES-09)")
                .register(registry);

        Gauge.builder("dome_key_migration_audit_completeness", this,
                        m -> m.auditTotalFinal.get() == 0
                                ? 0.0
                                : (double) m.auditWithEvidence.get() / m.auditTotalFinal.get())
                .description("Ratio of terminal-status records with audit evidence URI vs. total")
                .register(registry);
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /**
     * Records a re-issuance outcome counter with dynamic tags.
     * Counter instances are registered on-the-fly to support arbitrary
     * (outcome, reason) combinations without pre-declaring all label values.
     *
     * @param outcome short outcome label, e.g. "ok", "skipped", "failed"
     * @param reason  reason sub-label, e.g. "expired", "revoked", "hash_mismatch"
     */
    public void recordReissuance(String outcome, String reason) {
        Counter.builder("dome_key_migration_reissuance_total")
                .description("Number of credentials processed per outcome during re-issuance")
                .tags("outcome", outcome, "reason", reason)
                .register(registry)
                .increment();
    }

    /**
     * Increments the hash-mismatch counter.
     */
    public void recordHashMismatch() {
        hashMismatchCounter.increment();
    }

    /**
     * Starts a new Timer sample for measuring migration duration.
     *
     * @return a {@link Timer.Sample} that must be stopped via {@link #stopTimer(Timer.Sample)}
     */
    public Timer.Sample startTimer() {
        return Timer.start(registry);
    }

    /**
     * Stops the timer sample and records the elapsed duration.
     *
     * @param sample the sample returned by {@link #startTimer()}
     */
    public void stopTimer(Timer.Sample sample) {
        sample.stop(migrationTimer);
    }

    /**
     * Signals that one terminal-status record has an audit evidence URI.
     * Called by the audit adapter when {@code recordPlanAOk} persists successfully.
     */
    public void incrementAuditWithEvidence() {
        auditWithEvidence.incrementAndGet();
        auditTotalFinal.incrementAndGet();
    }

    /**
     * Signals that one terminal-status record does NOT have an audit evidence URI.
     * Called by the audit adapter when {@code recordFailure} persists.
     */
    public void incrementAuditTotalOnly() {
        auditTotalFinal.incrementAndGet();
    }

}






