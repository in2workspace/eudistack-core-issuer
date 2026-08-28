package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;

class IssuanceMetricsTest {

    private SimpleMeterRegistry registry;
    private IssuanceMetrics issuanceMetrics;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        issuanceMetrics = new IssuanceMetrics(registry);
    }

    @AfterEach
    void tearDown() {
        // IssuanceMetrics reads the tenant from MDC (bridged from the Reactor
        // context by MdcContextConfig), so it must not leak across tests.
        MDC.remove(TENANT_DOMAIN_CONTEXT_KEY);
        registry.close();
    }

    @Test
    void recordSuccess_tagsCounterAndTimerWithTenant() {
        MDC.put(TENANT_DOMAIN_CONTEXT_KEY, "kpmg");
        var sample = issuanceMetrics.startTimer();

        issuanceMetrics.recordSuccess(sample, "config-1", "email");

        assertThat(registry.find("issuance.requests").tag("tenant", "kpmg").counter()).isNotNull();
        assertThat(registry.find("issuance.duration").tag("tenant", "kpmg").timer()).isNotNull();
        // AC-04 / conv-observability.md §3: canonical tag key alongside the legacy "tenant" tag.
        assertThat(registry.find("issuance.requests").tag("tenant.id", "kpmg").counter()).isNotNull();
        assertThat(registry.find("issuance.duration").tag("tenant.id", "kpmg").timer()).isNotNull();
    }

    @Test
    void recordError_tagsCounterAndTimerWithTenant() {
        MDC.put(TENANT_DOMAIN_CONTEXT_KEY, "kpmg");
        var sample = issuanceMetrics.startTimer();

        issuanceMetrics.recordError(sample, "config-1", "email");

        assertThat(registry.find("issuance.requests").tag("tenant", "kpmg").tag("outcome", "error").counter()).isNotNull();
        assertThat(registry.find("issuance.duration").tag("tenant", "kpmg").tag("outcome", "error").timer()).isNotNull();
        // AC-04 / conv-observability.md §3: canonical tag key alongside the legacy "tenant" tag.
        assertThat(registry.find("issuance.requests").tag("tenant.id", "kpmg").tag("outcome", "error").counter()).isNotNull();
        assertThat(registry.find("issuance.duration").tag("tenant.id", "kpmg").tag("outcome", "error").timer()).isNotNull();
    }

    @Test
    void recordTokenRequest_tagsCounterWithTenant() {
        MDC.put(TENANT_DOMAIN_CONTEXT_KEY, "sandbox");

        issuanceMetrics.recordTokenRequest("authorization_code", "success");

        assertThat(registry.find("oid4vci.token.requests").tag("tenant", "sandbox").counter()).isNotNull();
    }

    @Test
    void recordIdempotencyCacheHit_tagsCounterWithTenant() {
        MDC.put(TENANT_DOMAIN_CONTEXT_KEY, "sandbox");

        issuanceMetrics.recordIdempotencyCacheHit();

        assertThat(registry.find("idempotency.cache.hits").tag("tenant", "sandbox").counter()).isNotNull();
    }

    @Test
    void missingTenant_fallsBackToUnknown() {
        issuanceMetrics.recordTokenRequest("authorization_code", "success");
        issuanceMetrics.recordIdempotencyCacheHit();

        assertThat(registry.find("oid4vci.token.requests").tag("tenant", "unknown").counter()).isNotNull();
        assertThat(registry.find("idempotency.cache.hits").tag("tenant", "unknown").counter()).isNotNull();
    }

    @Test
    void blankTenant_fallsBackToUnknown() {
        MDC.put(TENANT_DOMAIN_CONTEXT_KEY, "   ");

        issuanceMetrics.recordTokenRequest("authorization_code", "success");
        issuanceMetrics.recordIdempotencyCacheHit();

        assertThat(registry.find("oid4vci.token.requests").tag("tenant", "unknown").counter()).isNotNull();
        assertThat(registry.find("idempotency.cache.hits").tag("tenant", "unknown").counter()).isNotNull();
    }
}
