package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.spi.CallerIdentityPort;
import software.amazon.awssdk.services.sts.StsAsyncClient;

import java.util.concurrent.CompletionException;

/** {@link CallerIdentityPort} over STS {@code GetCallerIdentity}. */
public class AwsCallerIdentityAdapter implements CallerIdentityPort {

    private final StsAsyncClient client;

    public AwsCallerIdentityAdapter(StsAsyncClient client) {
        this.client = client;
    }

    @Override
    public String callerArn() {
        try {
            String arn = client.getCallerIdentity().join().arn();
            if (arn == null || arn.isBlank()) {
                throw new OnboardingFailedException("STS GetCallerIdentity returned no ARN");
            }
            return arn;
        } catch (CompletionException e) {
            throw new OnboardingFailedException("could not read the caller identity (STS GetCallerIdentity failed: "
                    + e.getCause().getClass().getSimpleName() + ")", e.getCause());
        }
    }
}
