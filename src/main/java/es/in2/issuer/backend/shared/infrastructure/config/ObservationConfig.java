package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.common.KeyValue;
import io.micrometer.observation.ObservationFilter;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Configuration(proxyBeanMethods = false)
public class ObservationConfig {

    private static final String UNKNOWN_TENANT = "unknown";

    @Bean
    ObservedAspect observedAspect(ObservationRegistry observationRegistry) {
        return new ObservedAspect(observationRegistry);
    }

    @Bean
    public ObservationFilter globalObservationFilter() {
        return context -> {
            context.addLowCardinalityKeyValue(KeyValue.of("component", "issuer-backend"));
            context.addLowCardinalityKeyValue(KeyValue.of("tenant", currentTenant()));
            return context;
        };
    }

    private static String currentTenant() {
        String tenant = MDC.get(TENANT_DOMAIN_CONTEXT_KEY);
        return tenant == null || tenant.isBlank() ? UNKNOWN_TENANT : tenant;
    }
}
