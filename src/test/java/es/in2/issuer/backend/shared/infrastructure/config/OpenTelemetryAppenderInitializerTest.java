package es.in2.issuer.backend.shared.infrastructure.config;

import io.opentelemetry.api.OpenTelemetry;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;

class OpenTelemetryAppenderInitializerTest {

    @Test
    void afterPropertiesSet_SpringManagedOpenTelemetry_InstallsItInTheLogbackAppenders() {
        OpenTelemetryAppenderInitializer initializer = new OpenTelemetryAppenderInitializer(OpenTelemetry.noop());

        assertThatCode(initializer::afterPropertiesSet).doesNotThrowAnyException();
    }
}
