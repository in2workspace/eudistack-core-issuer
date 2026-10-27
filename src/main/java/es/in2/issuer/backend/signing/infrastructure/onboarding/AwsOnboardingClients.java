package es.in2.issuer.backend.signing.infrastructure.onboarding;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.sts.StsAsyncClient;

import java.net.URI;
import java.time.Duration;

/**
 * AWS clients of the onboarding tool. Credentials come from the SDK default chain (the task role on ECS, SSO
 * on a laptop) unless a provider is given, which only tests do. {@code endpoint} is for emulators such as
 * LocalStack and applies to KMS and STS alike.
 */
public final class AwsOnboardingClients {

    private static final Duration ATTEMPT_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(60);

    private AwsOnboardingClients() {}

    /** @param region {@code null} lets the SDK resolve it (AWS_REGION, profile) */
    public static KmsAsyncClient kms(String region, URI endpoint, AwsCredentialsProvider credentials) {
        var builder = KmsAsyncClient.builder().overrideConfiguration(c -> c
                .apiCallAttemptTimeout(ATTEMPT_TIMEOUT).apiCallTimeout(CALL_TIMEOUT));
        if (region != null) {
            builder.region(Region.of(region));
        }
        if (endpoint != null) {
            builder.endpointOverride(endpoint);
        }
        if (credentials != null) {
            builder.credentialsProvider(credentials);
        }
        return builder.build();
    }

    /** @param region {@code null} lets the SDK resolve it (AWS_REGION, profile) */
    public static StsAsyncClient sts(String region, URI endpoint, AwsCredentialsProvider credentials) {
        var builder = StsAsyncClient.builder().overrideConfiguration(c -> c
                .apiCallAttemptTimeout(ATTEMPT_TIMEOUT).apiCallTimeout(CALL_TIMEOUT));
        if (region != null) {
            builder.region(Region.of(region));
        }
        if (endpoint != null) {
            builder.endpointOverride(endpoint);
        }
        if (credentials != null) {
            builder.credentialsProvider(credentials);
        }
        return builder.build();
    }
}
