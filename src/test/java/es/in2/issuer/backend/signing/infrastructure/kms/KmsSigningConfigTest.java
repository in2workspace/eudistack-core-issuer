package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KmsSigningConfigTest {

    @Configuration
    @EnableConfigurationProperties(KmsSigningProperties.class)
    static class PropertiesOnly {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesOnly.class, KmsSigningConfig.class);

    @Test
    void context_defaultProperties_createsNoKmsBeans() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(KmsAsyncClient.class);
            assertThat(context).doesNotHaveBean(KmsSigningPort.class);
            KmsSigningProperties props = context.getBean(KmsSigningProperties.class);
            assertThat(props.enabled()).isFalse();
            assertThat(props.callTimeout()).isEqualTo(Duration.ofSeconds(10));
            assertThat(props.maxRetries()).isEqualTo(3);
            assertThat(props.initialBackoff()).isEqualTo(Duration.ofSeconds(1));
            assertThat(props.maxBackoff()).isEqualTo(Duration.ofSeconds(5));
        });
    }

    @Test
    void context_explicitlyDisabled_createsNoKmsBeans() {
        runner.withPropertyValues("issuer.signing.kms.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(KmsSigningPort.class));
    }

    @Test
    void properties_enabledWithoutRegion_failsFast() {
        assertThatThrownBy(() -> new KmsSigningProperties(
                true, " ", null, Duration.ofSeconds(10), 3, Duration.ofSeconds(1), Duration.ofSeconds(5)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("region");
    }
}
