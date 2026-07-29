package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IssuanceMetricsTest {

    private SimpleMeterRegistry registry;
    private IssuanceMetrics issuanceMetrics;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        issuanceMetrics = new IssuanceMetrics(registry);
    }

    @Test
    void recordSuccess_tagsCounterAndTimerWithTenant() {
        var sample = issuanceMetrics.startTimer();

        issuanceMetrics.recordSuccess(sample, "config-1", "email");

        assertThat(registry.find("issuance.requests").tag("tenant", "kpmg").counter()).isNotNull();
        assertThat(registry.find("issuance.duration").tag("tenant", "kpmg").timer()).isNotNull();
    }

    @Test
    void recordError_tagsCounterAndTimerWithTenant() {
        var sample = issuanceMetrics.startTimer();

        issuanceMetrics.recordError(sample, "config-1", "email");

        assertThat(registry.find("issuance.requests").tag("tenant", "kpmg").tag("outcome", "error").counter()).isNotNull();
        assertThat(registry.find("issuance.duration").tag("tenant", "kpmg").tag("outcome", "error").timer()).isNotNull();
    }

    @Test
    void recordTokenRequest_tagsCounterWithTenant() {
        issuanceMetrics.recordTokenRequest("authorization_code", "success");

        assertThat(registry.find("oid4vci.token.requests").tag("tenant", "sandbox").counter()).isNotNull();
    }

    @Test
    void recordIdempotencyCacheHit_tagsCounterWithTenant() {
        issuanceMetrics.recordIdempotencyCacheHit();

        assertThat(registry.find("idempotency.cache.hits").tag("tenant", "sandbox").counter()).isNotNull();
    }

    @Test
    void nullOrBlankTenant_fallsBackToUnknown() {
        issuanceMetrics.recordTokenRequest("authorization_code", "success");
        issuanceMetrics.recordIdempotencyCacheHit();

        assertThat(registry.find("oid4vci.token.requests").tag("tenant", "unknown").counter()).isNotNull();
        assertThat(registry.find("idempotency.cache.hits").tag("tenant", "unknown").counter()).isNotNull();
    }
}
