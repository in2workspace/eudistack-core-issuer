package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicBoolean;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Component
public class IssuanceMetrics {

    private static final String TAG_TENANT = "tenant";
    private static final String UNKNOWN_TENANT = "unknown";

    static final String CREDENTIAL_ISSUED = "business.credential.issued";
    private static final String TAG_CONFIGURATION_ID = "configuration_id";
    private static final String TAG_OUTCOME = "outcome";
    static final String OUTCOME_OK = "ok";
    static final String OUTCOME_ERROR = "error";

    private final MeterRegistry meterRegistry;

    private final AtomicBoolean credentialIssuedFailureLogged = new AtomicBoolean(false);

    public IssuanceMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    public Timer.Sample startTimer() {
        return Timer.start(meterRegistry);
    }

    public void recordSuccess(Timer.Sample sample, String configurationId, String delivery) {
        sample.stop(Timer.builder("issuance.duration")
                .tag(TAG_TENANT, currentTenant())
                .tag("configuration_id", configurationId)
                .tag("delivery", delivery)
                .tag("outcome", "success")
                .register(meterRegistry));
        counter(configurationId, delivery, "success").increment();
    }

    public void recordError(Timer.Sample sample, String configurationId, String delivery) {
        sample.stop(Timer.builder("issuance.duration")
                .tag(TAG_TENANT, currentTenant())
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

    public void recordCredentialIssuedOk(String configurationId) {
        recordCredentialIssued(OUTCOME_OK, configurationId);
    }

    /** Cuenta una credencial que el holder pidió y no obtuvo — {@code outcome=error}. */
    public void recordCredentialIssuedError(String configurationId) {
        recordCredentialIssued(OUTCOME_ERROR, configurationId);
    }

    private void recordCredentialIssued(String outcome, String configurationId) {
        // Defensivo a propósito: los dos call sites llaman desde doOnSuccess/doOnError, donde
        // una excepción NO queda contenida — Reactor la enruta por Operators.onOperatorError y
        // convertiría una credencial ya firmada y entregada en un 500 para el wallet.
        try {
            Counter.builder(CREDENTIAL_ISSUED)
                    .tag(TAG_TENANT, currentTenant())
                    .tag(TAG_CONFIGURATION_ID, safeTag(configurationId))
                    .tag(TAG_OUTCOME, outcome)
                    .register(meterRegistry)
                    .increment();
        } catch (RuntimeException ex) {
            if (credentialIssuedFailureLogged.compareAndSet(false, true)) {
                log.warn("Could not record the {} counter; business metric disabled for this JVM: {}",
                        CREDENTIAL_ISSUED, ex.toString());
            }
        }
    }

    private static String safeTag(String value) {
        return value == null || value.isBlank() ? UNKNOWN_TENANT : value;
    }

    private Counter counter(String configurationId, String delivery, String outcome) {
        return Counter.builder("issuance.requests")
                .tag(TAG_TENANT, currentTenant())
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
