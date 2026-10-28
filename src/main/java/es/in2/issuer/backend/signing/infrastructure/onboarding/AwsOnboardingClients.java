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
 *
 * <p>The SDK also reads endpoint URLs from its configuration: the variables {@code AWS_ENDPOINT_URL} and
 * {@code AWS_ENDPOINT_URL_<SERVICE>}, the system properties {@code aws.endpointUrl*} and {@code endpoint_url} of the
 * profile. In production mode they are ignored, so a redirected STS cannot falsify the identity the tool records as the
 * actor: the SDK is told so through the system property {@link #IGNORE_CONFIGURED_ENDPOINT_URLS}, which is process wide
 * (the tool is a process of its own that ends with the run).
 */
public final class AwsOnboardingClients {

    /** System property of the SDK ({@code SdkSystemSetting.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS}). */
    static final String IGNORE_CONFIGURED_ENDPOINT_URLS = "aws.ignoreConfiguredEndpointUrls";

    private static final Duration ATTEMPT_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(60);

    private AwsOnboardingClients() {}

    /** @param region {@code null} lets the SDK resolve it (AWS_REGION, profile) */
    public static KmsAsyncClient kms(String region, URI endpoint, AwsCredentialsProvider credentials) {
        return kms(region, endpoint, credentials, false);
    }

    /**
     * @param region                       {@code null} lets the SDK resolve it (AWS_REGION, profile)
     * @param ignoreConfiguredEndpointUrls the endpoint URLs the SDK reads from its configuration are ignored (production)
     */
    public static KmsAsyncClient kms(String region, URI endpoint, AwsCredentialsProvider credentials,
                                     boolean ignoreConfiguredEndpointUrls) {
        ignoreConfiguredEndpointUrlsIf(ignoreConfiguredEndpointUrls);
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
        return sts(region, endpoint, credentials, false);
    }

    /**
     * @param region                       {@code null} lets the SDK resolve it (AWS_REGION, profile)
     * @param ignoreConfiguredEndpointUrls the endpoint URLs the SDK reads from its configuration are ignored (production)
     */
    public static StsAsyncClient sts(String region, URI endpoint, AwsCredentialsProvider credentials,
                                     boolean ignoreConfiguredEndpointUrls) {
        ignoreConfiguredEndpointUrlsIf(ignoreConfiguredEndpointUrls);
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

    private static void ignoreConfiguredEndpointUrlsIf(boolean ignore) {
        if (ignore) {
            System.setProperty(IGNORE_CONFIGURED_ENDPOINT_URLS, "true");
        }
    }
}
