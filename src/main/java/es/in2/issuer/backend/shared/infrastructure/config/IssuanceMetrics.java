package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Component
public class IssuanceMetrics {

    private static final String TAG_TENANT = "tenant";
    private static final String TAG_TENANT_ID = "tenant.id";
    private static final String UNKNOWN_TENANT = "unknown";

    private final MeterRegistry meterRegistry;

    public IssuanceMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    public Timer.Sample startTimer() {
        return Timer.start(meterRegistry);
    }

    public void recordSuccess(Timer.Sample sample, String configurationId, String delivery) {
        sample.stop(Timer.builder("issuance.duration")
                .tag(TAG_TENANT, currentTenant())
                .tag(TAG_TENANT_ID, currentTenant())
                .tag("configuration_id", configurationId)
                .tag("delivery", delivery)
                .tag("outcome", "success")
                .register(meterRegistry));
        counter(configurationId, delivery, "success").increment();
    }

    public void recordError(Timer.Sample sample, String configurationId, String delivery) {
        sample.stop(Timer.builder("issuance.duration")
                .tag(TAG_TENANT, currentTenant())
                .tag(TAG_TENANT_ID, currentTenant())
                .tag("configuration_id", configurationId)
                .tag("delivery", delivery)
                .tag("outcome", "error")
                .register(meterRegistry));
        counter(configurationId, delivery, "error").increment();
    }

    public void recordIdempotencyCacheHit() {
        Counter.builder("idempotency.cache.hits")
                .tag(TAG_TENANT, currentTenant())
                .register(meterRegistry)
                .increment();
    }

    public void recordTokenRequest(String grantType, String outcome) {
        Counter.builder("oid4vci.token.requests")
                .tag(TAG_TENANT, currentTenant())
                .tag("grant_type", grantType)
                .tag("outcome", outcome)
                .register(meterRegistry)
                .increment();
    }

    private Counter counter(String configurationId, String delivery, String outcome) {
        return Counter.builder("issuance.requests")
                .tag(TAG_TENANT, currentTenant())
                .tag(TAG_TENANT_ID, currentTenant())
                .tag("configuration_id", configurationId)
                .tag("delivery", delivery)
                .tag("outcome", outcome)
                .register(meterRegistry);
    }

    private static String currentTenant() {
        String tenant = MDC.get(TENANT_DOMAIN_CONTEXT_KEY);
        return tenant == null || tenant.isBlank() ? UNKNOWN_TENANT : tenant;
    }
}
