package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.common.KeyValue;
import io.micrometer.observation.ObservationFilter;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Observation setup. CustomObservationHandler is not registered here: Spring Boot already adds
 * every ObservationHandler bean to the registry, and registering it again runs it twice.
 */
@Configuration
public class ObservationConfig {

    private static final String UNKNOWN_TENANT = "unknown";

    /**
     * Registers the AOP aspect to enable the use of @Observed.
     * Spring Boot auto-configures and injects the base ObservationRegistry.
     */
    @Bean
    public ObservedAspect observedAspect(ObservationRegistry observationRegistry) {
        return new ObservedAspect(observationRegistry);
    }

    /** Tags every observation (spans and the metrics derived from it) with the component and tenant. */
    @Bean
    public ObservationFilter globalObservationFilter() {
        return context -> {
            context.addLowCardinalityKeyValue(KeyValue.of("component", MicrometerMetricsConfig.COMPONENT));
            context.addLowCardinalityKeyValue(KeyValue.of("tenant", currentTenant()));
            return context;
        };
    }

    private static String currentTenant() {
        String tenant = MDC.get(TENANT_DOMAIN_CONTEXT_KEY);
        return tenant == null || tenant.isBlank() ? UNKNOWN_TENANT : tenant;
    }
}
