package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyReconciler;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.sts.StsAsyncClient;

import java.time.Clock;
import java.util.UUID;

/** Builds the real collaborators of the onboarding tool: AWS KMS and STS, JDBC and the logging audit sink. */
public class OnboardingWiring implements OnboardingCli.Wiring {

    private final AwsCredentialsProvider credentials;

    /** Credentials from the SDK default chain. */
    public OnboardingWiring() {
        this(null);
    }

    /** @param credentials fixed credentials; for tests against an emulator only */
    public OnboardingWiring(AwsCredentialsProvider credentials) {
        this.credentials = credentials;
    }

    @Override
    public OnboardingCli.Services open(OnboardingSettings settings) {
        KmsAsyncClient kmsClient = AwsOnboardingClients.kms(settings.kmsRegion(), settings.kmsEndpoint(), credentials);
        StsAsyncClient stsClient = AwsOnboardingClients.sts(settings.kmsRegion(), settings.kmsEndpoint(), credentials);
        var kms = new AwsKmsKeyAdministrationAdapter(kmsClient, null);
        var store = new JdbcOwnKeyStore(settings.dbUrl(), settings.dbUser(), settings.dbPassword(),
                new LoggingSigningConfigurationAuditSink());
        var onboarding = new OwnKeyOnboarding(kms, store, new AwsCallerIdentityAdapter(stsClient), Clock.systemUTC(),
                () -> UUID.randomUUID().toString(), settings.deletionWindowDays());
        var reconciler = new OwnKeyReconciler(kms, store, settings.deletionWindowDays());
        return new OnboardingCli.Services() {
            @Override
            public OwnKeyOnboarding onboarding() {
                return onboarding;
            }

            @Override
            public OwnKeyReconciler reconciler() {
                return reconciler;
            }

            @Override
            public void close() {
                kmsClient.close();
                stsClient.close();
            }
        };
    }
}
