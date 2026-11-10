package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

class KmsSigningConfigTest {

    @Configuration
    @EnableConfigurationProperties(KmsSigningProperties.class)
    static class PropertiesOnly {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesOnly.class, KmsSigningConfig.class);

    /** Building the client needs a region: it is left to the first signature, so startup never needs one. */
    @Test
    void context_createsThePort_butNotTheClient() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(KmsSigningPort.class);
            assertThat(context.getBeanFactory().containsSingleton("kmsAsyncClient")).isFalse();
        });
    }

    @Test
    void properties_endpoint_isOnlyForEmulators() {
        runner.withPropertyValues("issuer.signing.kms.endpoint=http://localstack:4566")
                .run(context -> assertThat(context.getBean(KmsSigningProperties.class).endpoint())
                        .isEqualTo(URI.create("http://localstack:4566")));
        runner.run(context -> assertThat(context.getBean(KmsSigningProperties.class).endpoint()).isNull());
    }
}
