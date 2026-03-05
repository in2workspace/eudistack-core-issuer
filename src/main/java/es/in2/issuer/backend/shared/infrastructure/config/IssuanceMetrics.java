package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

@Component
public class IssuanceMetrics {

    private final MeterRegistry meterRegistry;

    public IssuanceMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    public Timer.Sample startTimer() {
        return Timer.start(meterRegistry);
    }

    public void recordSuccess(Timer.Sample sample, String configurationId, String delivery) {
        sample.stop(Timer.builder("issuance.duration")
                .tag("configuration_id", configurationId)
                .tag("delivery", delivery)
                .tag("outcome", "success")
                .register(meterRegistry));
        counter(configurationId, delivery, "success").increment();
    }

    public void recordError(Timer.Sample sample, String configurationId, String delivery) {
        sample.stop(Timer.builder("issuance.duration")
                .tag("configuration_id", configurationId)
                .tag("delivery", delivery)
                .tag("outcome", "error")
                .register(meterRegistry));
        counter(configurationId, delivery, "error").increment();
    }

    public void recordValidationFailure(String reason) {
        Counter.builder("issuance.validation.failures")
                .tag("reason", reason)
                .register(meterRegistry)
                .increment();
    }

    public void recordIdempotencyCacheHit() {
        Counter.builder("idempotency.cache.hits")
                .register(meterRegistry)
                .increment();
    }

    private Counter counter(String configurationId, String delivery, String outcome) {
        return Counter.builder("issuance.requests")
                .tag("configuration_id", configurationId)
                .tag("delivery", delivery)
                .tag("outcome", outcome)
                .register(meterRegistry);
    }
}
