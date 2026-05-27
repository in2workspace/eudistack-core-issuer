package es.in2.issuer.backend.dome.infrastructure.observability;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class SyncCredentialsMetrics {

    private final MeterRegistry registry;

    public SyncCredentialsMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    public void recordRecoveryAttempt(String tenant, String outcome, String reason, boolean idempotentHit, String mode) {
        Counter.builder("dome_wallet_recovery_attempts_total")
                .description("Total number of DOME wallet recovery attempts")
                .tag("tenant", tenant != null ? tenant : "unknown")
                .tag("outcome", outcome)
                .tag("reason", reason != null ? reason : "none")
                .tag("idempotent_hit", String.valueOf(idempotentHit))
                .tag("mode", mode)
                .register(registry)
                .increment();
    }

    public void recordRecoveryDuration(Duration duration) {
        Timer.builder("dome_wallet_recovery_duration_ms")
                .description("Time taken to process a DOME wallet recovery request")
                .publishPercentileHistogram()
                .register(registry)
                .record(duration);
    }
}