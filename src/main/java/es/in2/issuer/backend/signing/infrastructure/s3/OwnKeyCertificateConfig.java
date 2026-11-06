package es.in2.issuer.backend.signing.infrastructure.s3;

import es.in2.issuer.backend.signing.domain.spi.OwnKeyCertificatePort;
import es.in2.issuer.backend.signing.infrastructure.properties.OwnKeyCertificateProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3AsyncClientBuilder;

import java.time.Duration;

/**
 * S3 beans of the own-key certificates, created only when {@code issuer.signing.certificates.arn}
 * ({@code S3_CERTIFICATE_ARN}) is set and not blank ({@link OwnKeyCertificatesConfigured}). Region and credentials
 * come from the SDK default chain (on ECS, {@code AWS_REGION} and the runtime role).
 *
 * <p>Unlike the KMS client, the S3 client is built at startup: a deployment that sets the ARN means to use own
 * keys, so a missing region stops the Issuer at once instead of failing every own-key tenant later.
 */
@Configuration
@Conditional(OwnKeyCertificatesConfigured.class)
public class OwnKeyCertificateConfig {

    /** Bound of one read, retries of the SDK included. Fixed, like the KMS timeouts. */
    static final Duration READ_TIMEOUT = Duration.ofSeconds(10);

    @Bean(destroyMethod = "close")
    S3AsyncClient ownKeyCertificateS3Client(OwnKeyCertificateProperties properties) {
        return clientBuilder(properties).build();
    }

    /** Endpoint and the timeout of one read; region and credentials are left to the SDK or the caller. */
    static S3AsyncClientBuilder clientBuilder(OwnKeyCertificateProperties properties) {
        S3AsyncClientBuilder builder = S3AsyncClient.builder()
                .overrideConfiguration(c -> c.apiCallTimeout(READ_TIMEOUT));
        if (properties.endpoint() != null) {
            // Emulators such as LocalStack do not resolve bucket names as subdomains.
            builder.endpointOverride(properties.endpoint()).forcePathStyle(true);
        }
        return builder;
    }

    @Bean
    OwnKeyCertificatePort ownKeyCertificatePort(S3AsyncClient ownKeyCertificateS3Client,
                                                OwnKeyCertificateProperties properties) {
        return new S3OwnKeyCertificateAdapter(ownKeyCertificateS3Client, properties);
    }
}
