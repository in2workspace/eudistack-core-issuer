package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding;
import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyReconciler;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.sts.StsAsyncClient;

import javax.sql.DataSource;
import java.time.Clock;
import java.util.UUID;

/** Builds the real collaborators of the onboarding tool: AWS KMS and STS, JDBC and the logging audit sink. */
public class OnboardingWiring implements OnboardingCli.Wiring {

    /** In the opt-in source set src/audit-starter, compiled only with -PauditStarter. */
    static final String OUTBOX_SINK_FACTORY =
            "es.in2.issuer.backend.signing.infrastructure.onboarding.audit.OutboxAuditSinkFactory";

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
        var kms = new AwsKmsKeyAdministrationAdapter(kmsClient, settings.keyPolicy());
        DataSource dataSource = new DriverManagerDataSource(settings.dbUrl(), settings.dbUser(), settings.dbPassword());
        AuditSinkHandle auditSink = openAuditSink(settings, dataSource, kmsClient, stsClient);
        var store = new JdbcOwnKeyStore(dataSource, auditSink.sink());
        var onboarding = new OwnKeyOnboarding(kms, store, new AwsCallerIdentityAdapter(stsClient), Clock.systemUTC(),
                () -> UUID.randomUUID().toString(), settings.deletionWindowDays());
        var reconciler = new OwnKeyReconciler(kms, store, new AwsCallerIdentityAdapter(stsClient), Clock.systemUTC(),
                settings.deletionWindowDays());
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
                auditSink.close();
                kmsClient.close();
                stsClient.close();
            }
        };
    }

    /**
     * The log sink, or the outbox sink of the audit starter, loaded by name: a build without the starter does not
     * have the class and the run fails with a message that says so.
     */
    private static AuditSinkHandle openAuditSink(OnboardingSettings settings, DataSource dataSource,
                                                 AutoCloseable... toCloseOnFailure) {
        if (settings.auditSink() == OnboardingSettings.AuditSinkMode.LOG) {
            return AuditSinkHandle.of(new LoggingSigningConfigurationAuditSink());
        }
        try {
            Class<?> factory = Class.forName(OUTBOX_SINK_FACTORY);
            return ((AuditSinkFactory) factory.getDeclaredConstructor().newInstance()).open(dataSource);
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            closeQuietly(toCloseOnFailure);
            throw new OnboardingFailedException("OWN_KEY_AUDIT_SINK=outbox needs the audit starter and this build does "
                    + "not include it: it was built without -PauditStarter (see docs/own-key-onboarding-tool.md)");
        } catch (ReflectiveOperationException e) {
            closeQuietly(toCloseOnFailure);
            throw new OnboardingFailedException("the outbox audit sink could not be created", e);
        }
    }

    private static void closeQuietly(AutoCloseable... closeables) {
        for (AutoCloseable closeable : closeables) {
            try {
                closeable.close();
            } catch (Exception e) {
                // The run is already failing with its own message.
            }
        }
    }
}
