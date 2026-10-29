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
            assertThat(props.initialBackoff()).isEqualTo(Duration.ofMillis(200));
            assertThat(props.maxBackoff()).isEqualTo(Duration.ofSeconds(5));
            assertThat(props.deadline()).isEqualTo(Duration.ofSeconds(45));
        });
    }

    @Test
    void context_explicitlyDisabled_createsNoKmsBeans() {
        runner.withPropertyValues("issuer.signing.kms.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(KmsSigningPort.class));
    }

    @Test
    void properties_enabledWithoutRegion_failsFast() {
        Duration callTimeout = Duration.ofSeconds(10);
        Duration initialBackoff = Duration.ofMillis(200);
        Duration maxBackoff = Duration.ofSeconds(5);
        Duration deadline = Duration.ofSeconds(45);

        assertThatThrownBy(() -> new KmsSigningProperties(
                true, " ", null, callTimeout, 3, initialBackoff, maxBackoff, deadline))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("region");
    }

    @Test
    void properties_deadlineShorterThanTheCallTimeout_failsFast() {
        Duration callTimeout = Duration.ofSeconds(10);
        Duration initialBackoff = Duration.ofMillis(200);
        Duration maxBackoff = Duration.ofSeconds(5);
        Duration deadline = Duration.ofSeconds(9);

        assertThatThrownBy(() -> new KmsSigningProperties(
                true, "eu-west-1", null, callTimeout, 3, initialBackoff, maxBackoff, deadline))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("deadline");
    }

    @Test
    void worstCaseSigningDuration_neverExceedsTheDeadline() {
        Duration callTimeout = Duration.ofSeconds(10);
        Duration initialBackoff = Duration.ofMillis(200);
        Duration maxBackoff = Duration.ofSeconds(5);

        // 4 attempts of 10 s and 3 waits of at most 5 s would be 55 s: the deadline caps it.
        assertThat(new KmsSigningProperties(false, null, null, callTimeout, 3, initialBackoff, maxBackoff,
                Duration.ofSeconds(45)).worstCaseSigningDuration()).isEqualTo(Duration.ofSeconds(45));
        assertThat(new KmsSigningProperties(false, null, null, callTimeout, 3, initialBackoff, maxBackoff,
                Duration.ofSeconds(60)).worstCaseSigningDuration()).isEqualTo(Duration.ofSeconds(55));
    }
}
