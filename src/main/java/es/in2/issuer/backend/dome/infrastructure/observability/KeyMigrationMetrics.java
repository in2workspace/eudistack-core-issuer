package es.in2.issuer.backend.dome.infrastructure.observability;

import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class KeyMigrationMetrics {

    public enum ReissuanceOutcome {
        OK, SKIPPED, FAILED, HASH_MISMATCH;

        public String tagValue() {
            return name().toLowerCase();
        }
    }

    public enum ReissuanceReason {
        NONE, ALREADY_EXPIRED, REVOKED, ISSUANCE_ERROR, HASH_MISMATCH;

        public String tagValue() {
            return name().toLowerCase();
        }
    }

    private final MeterRegistry registry;

    /**
     * Injected for future gauge queries at the repository level.
     * The current gauge uses in-process accumulators for low-overhead sampling.
     */
    private final KmsKeyMigrationRepositoryPort migrationRepositoryPort;

    private final Timer migrationTimer;

    private final Counter hashMismatchCounter;

    private final AtomicLong auditWithEvidence = new AtomicLong(0);
    private final AtomicLong auditTotalFinal = new AtomicLong(0);

    /**
     * Pre-registered counters keyed by "outcome:reason".
     * All valid combinations are created at construction time to prevent
     * unbounded meter cardinality in production.
     */
    private final Map<String, Counter> reissuanceCounters = new ConcurrentHashMap<>();

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

        for (ReissuanceOutcome outcome : ReissuanceOutcome.values()) {
            for (ReissuanceReason reason : ReissuanceReason.values()) {
                String key = outcome.tagValue() + ":" + reason.tagValue();
                reissuanceCounters.put(key, Counter.builder("dome_key_migration_reissuance_total")
                        .description("Number of credentials processed per outcome during re-issuance")
                        .tags("outcome", outcome.tagValue(), "reason", reason.tagValue())
                        .register(registry));
            }
        }
    }

    public void recordReissuance(ReissuanceOutcome outcome, ReissuanceReason reason) {
        String key = outcome.tagValue() + ":" + reason.tagValue();
        Counter counter = reissuanceCounters.get(key);
        if (counter != null) {
            counter.increment();
        } else {
            throw new IllegalArgumentException(
                    "Unknown outcome/reason combination: " + key
                    + ". Use ReissuanceOutcome and ReissuanceReason constants.");
        }
    }

    public void recordHashMismatch() {
        hashMismatchCounter.increment();
    }

    public Timer.Sample startTimer() {
        return Timer.start(registry);
    }

    public void stopTimer(Timer.Sample sample) {
        sample.stop(migrationTimer);
    }

    public void incrementAuditWithEvidence() {
        auditWithEvidence.incrementAndGet();
        auditTotalFinal.incrementAndGet();
    }

    public void incrementAuditTotalOnly() {
        auditTotalFinal.incrementAndGet();
    }
}
