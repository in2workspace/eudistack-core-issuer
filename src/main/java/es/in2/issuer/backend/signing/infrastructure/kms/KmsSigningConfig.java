package es.in2.issuer.backend.signing.infrastructure.kms;

import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.KmsAsyncClientBuilder;

import java.time.Duration;

/**
 * KMS beans. The client is lazy: it is built by the first own-key signature (usually the startup
 * self-test), not at startup, because building it needs a region. Without one (local stack, tests,
 * deployments outside AWS) the issuer still starts and only own-key signing fails, with {@code KEY_UNUSABLE}.
 * Region and credentials come from the SDK default chain (on ECS, {@code AWS_REGION} and the runtime role).
 */
@Configuration
public class KmsSigningConfig {

    // Backstop only: the Reactor timeout in the adapter is the one that governs each attempt.
    private static final Duration SDK_TIMEOUT_MARGIN = Duration.ofSeconds(2);

    @Lazy
    @Bean(destroyMethod = "close")
    KmsAsyncClient kmsAsyncClient(KmsSigningProperties properties) {
        return clientBuilder(properties).build();
    }

    /** Endpoint, no SDK retries and timeout backstop; region and credentials are left to the SDK or the caller. */
    static KmsAsyncClientBuilder clientBuilder(KmsSigningProperties properties) {
        KmsAsyncClientBuilder builder = KmsAsyncClient.builder()
                .overrideConfiguration(c -> c
                        .retryStrategy(AwsRetryStrategy.doNotRetry())
                        .apiCallTimeout(KmsSigningTiming.DEFAULT.callTimeout().plus(SDK_TIMEOUT_MARGIN)));
        if (properties.endpoint() != null) {
            builder.endpointOverride(properties.endpoint());
        }
        return builder;
    }

    @Bean
    KmsSigningPort kmsSigningPort(ObjectProvider<KmsAsyncClient> kmsAsyncClient) {
        return new KmsSigningAdapter(kmsAsyncClient::getObject);
    }
}
