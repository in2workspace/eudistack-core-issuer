package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.core.instrument.Clock;
import io.micrometer.registry.otlp.OtlpConfig;
import io.micrometer.registry.otlp.OtlpMeterRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(name = "management.otlp.metrics.export.enabled", havingValue = "true")
public class OtlpGrpcMetricsConfig {

    @Bean
    public OtlpMeterRegistry otlpMeterRegistry(OtlpConfig otlpConfig, Clock clock) {
        return OtlpMeterRegistry.builder(otlpConfig)
                .clock(clock)
                .metricsSender(new OtlpGrpcMetricsSender())
                .build();
    }
}
