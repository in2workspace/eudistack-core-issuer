package es.in2.issuer.backend.shared.infrastructure.config;

import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter;
import io.opentelemetry.sdk.trace.export.SpanExporter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Adds a second, independent trace export path (gRPC → OTel Collector → Zipkin) alongside the
 * Spring Boot-managed HTTP exporter (management.otlp.tracing.endpoint, → Jaeger). Spring Boot
 * aggregates every {@link SpanExporter} bean in context into a single CompositeSpanExporter, so
 * this bean does not replace the existing exporter — both run side by side.
 */
@Configuration
@ConditionalOnProperty(name = "management.otlp.tracing.grpc.enabled", havingValue = "true")
public class OtlpGrpcTracingConfig {

    @Bean
    public SpanExporter otlpGrpcSpanExporter(
            @Value("${management.otlp.tracing.grpc.endpoint}") String endpoint) {
        return OtlpGrpcSpanExporter.builder()
                .setEndpoint(endpoint)
                .build();
    }
}
