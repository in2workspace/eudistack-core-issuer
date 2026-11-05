package es.in2.issuer.backend.signing.infrastructure.s3;

import es.in2.issuer.backend.signing.domain.spi.OwnKeyCertificatePort;
import es.in2.issuer.backend.signing.infrastructure.properties.OwnKeyCertificateProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3AsyncClientBuilder;

/**
 * S3 beans of the own-key certificates, created only when {@code issuer.signing.certificates.arn}
 * ({@code S3_CERTIFICATE_ARN}) is set and not blank. Credentials come from the SDK default chain (the runtime role on ECS).
 */
@Configuration
// Not @ConditionalOnProperty: application.yml maps S3_CERTIFICATE_ARN with an empty default, and an empty
// value would still match it.
@ConditionalOnExpression("!'${issuer.signing.certificates.arn:}'.isBlank()")
public class OwnKeyCertificateConfig {

    @Bean(destroyMethod = "close")
    S3AsyncClient ownKeyCertificateS3Client(OwnKeyCertificateProperties properties) {
        return clientBuilder(properties).build();
    }

    /** Region, endpoint and the timeout of one read; credentials are left to the caller. */
    static S3AsyncClientBuilder clientBuilder(OwnKeyCertificateProperties properties) {
        S3AsyncClientBuilder builder = S3AsyncClient.builder()
                .overrideConfiguration(c -> c.apiCallTimeout(properties.timeout()));
        if (properties.region() != null && !properties.region().isBlank()) {
            builder.region(Region.of(properties.region()));
        }
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
