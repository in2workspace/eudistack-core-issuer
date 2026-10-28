package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.KmsAsyncClientBuilder;

import java.time.Duration;

/**
 * KMS beans, created only when {@code issuer.signing.kms.enabled=true}. Credentials come from
 * the SDK default chain (the runtime role on ECS).
 */
@Configuration
@ConditionalOnProperty(prefix = "issuer.signing.kms", name = "enabled", havingValue = "true")
public class KmsSigningConfig {

    // Backstop only: the Reactor timeout in the adapter is the one that governs each attempt.
    private static final Duration SDK_TIMEOUT_MARGIN = Duration.ofSeconds(2);

    @Bean(destroyMethod = "close")
    KmsAsyncClient kmsAsyncClient(KmsSigningProperties properties) {
        return clientBuilder(properties).build();
    }

    /** Region, endpoint, no SDK retries and timeout backstop; credentials are left to the caller. */
    static KmsAsyncClientBuilder clientBuilder(KmsSigningProperties properties) {
        KmsAsyncClientBuilder builder = KmsAsyncClient.builder()
                .region(Region.of(properties.region()))
                .overrideConfiguration(c -> c
                        .retryStrategy(AwsRetryStrategy.doNotRetry())
                        .apiCallTimeout(properties.callTimeout().plus(SDK_TIMEOUT_MARGIN)));
        if (properties.endpoint() != null) {
            builder.endpointOverride(properties.endpoint());
        }
        return builder;
    }

    @Bean
    KmsSigningPort kmsSigningPort(KmsAsyncClient kmsAsyncClient, KmsSigningProperties properties) {
        return new KmsSigningAdapter(kmsAsyncClient, properties);
    }
}
