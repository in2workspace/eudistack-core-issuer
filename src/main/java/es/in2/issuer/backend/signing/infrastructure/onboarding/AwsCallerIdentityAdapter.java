package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.spi.CallerIdentityPort;
import software.amazon.awssdk.services.sts.StsAsyncClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import java.util.concurrent.CompletionException;

/** {@link CallerIdentityPort} over STS {@code GetCallerIdentity}. */
public class AwsCallerIdentityAdapter implements CallerIdentityPort {

    private final StsAsyncClient client;

    public AwsCallerIdentityAdapter(StsAsyncClient client) {
        this.client = client;
    }

    @Override
    public String callerArn() {
        String arn = identity().arn();
        if (arn == null || arn.isBlank()) {
            throw new OnboardingFailedException("STS GetCallerIdentity returned no ARN");
        }
        return arn;
    }

    /** The 12-digit id of the AWS account the credentials belong to. */
    public String callerAccount() {
        String account = identity().account();
        if (account == null || account.isBlank()) {
            throw new OnboardingFailedException("STS GetCallerIdentity returned no account");
        }
        return account;
    }

    private GetCallerIdentityResponse identity() {
        try {
            return client.getCallerIdentity().join();
        } catch (CompletionException e) {
            throw new OnboardingFailedException("could not read the caller identity (STS GetCallerIdentity failed: "
                    + e.getCause().getClass().getSimpleName() + ")", e.getCause());
        }
    }
}
