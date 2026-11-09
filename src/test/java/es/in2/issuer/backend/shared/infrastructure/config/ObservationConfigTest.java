package es.in2.issuer.backend.shared.infrastructure.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import es.in2.issuer.backend.shared.infrastructure.observability.CustomObservationHandler;
import io.micrometer.common.KeyValue;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.server.reactive.observation.ServerRequestObservationContext;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class ObservationConfigTest {

    private final ObservationConfig config = new ObservationConfig();
    private final Logger handlerLogger = (Logger) LoggerFactory.getLogger(CustomObservationHandler.class);
    private final Level originalLevel = handlerLogger.getLevel();

    @AfterEach
    void restoreLogLevel() {
        handlerLogger.setLevel(originalLevel);
        MDC.clear();
    }

    @Test
    void globalObservationFilter_AnyObservation_AddsTheComponentTag() {
        Observation.Context context = new Observation.Context();

        config.globalObservationFilter().map(context);

        assertThat(context.getLowCardinalityKeyValue("component"))
                .isEqualTo(KeyValue.of("component", "issuer-backend"));
    }

    @Test
    void globalObservationFilter_TenantInMdc_AddsTheTenantTag() {
        MDC.put("tenantDomain", "sandbox");
        Observation.Context context = new Observation.Context();

        config.globalObservationFilter().map(context);

        assertThat(context.getLowCardinalityKeyValue("tenant")).isEqualTo(KeyValue.of("tenant", "sandbox"));
    }

    @Test
    void globalObservationFilter_NoTenantInMdc_AddsTheUnknownTenantTag() {
        Observation.Context context = new Observation.Context();

        config.globalObservationFilter().map(context);

        assertThat(context.getLowCardinalityKeyValue("tenant")).isEqualTo(KeyValue.of("tenant", "unknown"));
    }

    @Test
    void globalObservationFilter_HttpObservationAfterTheMdcIsCleared_KeepsTheConventionTenant() {
        assertThat(stoppedHttpObservationTenant(Map.of("tenantDomain", "sandbox"))).isEqualTo("sandbox");
    }

    @Test
    void globalObservationFilter_HttpObservationWithoutTenant_ReportsTheUnknownTenant() {
        assertThat(stoppedHttpObservationTenant(Map.of())).isEqualTo("unknown");
    }

    /** Runs the real convention and filter in the order Micrometer applies them when an observation stops. */
    private String stoppedHttpObservationTenant(Map<String, Object> exchangeAttributes) {
        ServerRequestObservationContext context = new ServerRequestObservationContext(
                MockServerHttpRequest.get("/issuer/api").build(), new MockServerHttpResponse(), exchangeAttributes);
        AtomicReference<String> tenant = new AtomicReference<>();
        ObservationRegistry registry = ObservationRegistry.create();
        registry.observationConfig().observationFilter(config.globalObservationFilter());
        registry.observationConfig().observationHandler(new ObservationHandler<>() {
            @Override
            public boolean supportsContext(Observation.Context ignored) {
                return true;
            }

            @Override
            public void onStop(Observation.Context stopped) {
                tenant.set(stopped.getLowCardinalityKeyValue("tenant").getValue());
            }
        });

        Observation.createNotStarted(new TenantServerRequestObservationConvention(), () -> context, registry)
                .start()
                .stop();

        return tenant.get();
    }

    @Test
    void customObservationHandler_DebugEnabled_HandlesTheObservationLifecycle() {
        handlerLogger.setLevel(Level.DEBUG);
        ObservationRegistry registry = ObservationRegistry.create();
        registry.observationConfig().observationHandler(new CustomObservationHandler());

        Observation observation = Observation.start("issuer.test", registry);
        observation.error(new IllegalStateException("boom"));
        observation.stop();

        assertThat(observation.isNoop()).isFalse();
    }

    @Test
    void customObservationHandler_DebugDisabled_DoesNotSupportTheContext() {
        handlerLogger.setLevel(Level.INFO);

        assertThat(new CustomObservationHandler().supportsContext(new Observation.Context())).isFalse();
    }
}
