package es.in2.issuer.backend.signing.infrastructure.s3;

import es.in2.issuer.backend.signing.domain.spi.OwnKeyCertificatePort;
import es.in2.issuer.backend.signing.infrastructure.properties.OwnKeyCertificateProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class OwnKeyCertificateConfigTest {

    @Configuration
    @EnableConfigurationProperties(OwnKeyCertificateProperties.class)
    static class PropertiesOnly {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesOnly.class, OwnKeyCertificateConfig.class);

    @Test
    void context_withoutArn_createsNoCertificatePort() {
        runner.run(context -> assertThat(context).doesNotHaveBean(OwnKeyCertificatePort.class));
    }

    /** application.yml maps S3_CERTIFICATE_ARN with an empty default: unset, the property is empty. */
    @Test
    void context_emptyArn_createsNoCertificatePort() {
        runner.withPropertyValues("issuer.signing.certificates.arn=")
                .run(context -> assertThat(context).doesNotHaveBean(OwnKeyCertificatePort.class));
    }

    /**
     * The client takes its region from the SDK default chain (on ECS, {@code AWS_REGION}); the test gives it one
     * through that chain, so it does not depend on the AWS profile of the machine that runs it.
     */
    @Test
    void context_withArn_createsTheCertificatePort() {
        runner.withSystemProperties("aws.region=eu-west-1")
                .withPropertyValues("issuer.signing.certificates.arn=arn:aws:s3:::certs-bucket/issuer")
                .run(context -> assertThat(context).hasSingleBean(OwnKeyCertificatePort.class));
    }
}
