package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.metrics.MeterRegistryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MicrometerMetricsConfig {

    @Bean
    public MeterRegistryCustomizer<MeterRegistry> commonTagsCustomizer(
            @Value("${spring.application.name}") String appName) {
        return registry -> registry.config().commonTags(
                "application", appName,
                "component", "issuer-backend"
        );
    }
}
