package es.in2.issuer.backend.signing.infrastructure.onboarding.audit;

import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingCli;
import es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase;
import es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingWiring;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.execute;
import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.query;
import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.scalar;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The tool through its command line with {@code OWN_KEY_AUDIT_SINK=outbox}: the sink is loaded by name, the outbox
 * is created and a rejection reaches {@code public.audit_outbox}. Only STS is needed from LocalStack (the caller
 * identity); a rejection happens before anything is created in KMS. Run only with {@code -PauditStarter}.
 */
@Testcontainers
class OwnKeyOnboardingOutboxIT {

    private static final StaticCredentialsProvider CREDENTIALS =
            StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test"));

    @Container
    static final LocalStackContainer LOCALSTACK = new LocalStackContainer(DockerImageName.parse("localstack/localstack:4.14.0"))
            .withServices(LocalStackContainer.EnabledService.named("kms"), LocalStackContainer.EnabledService.named("sts"));

    private final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    private final ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    private final Map<String, String> env = new HashMap<>();
    private OnboardingCli cli;

    @TempDir
    Path directory;

    @BeforeEach
    void setUp() {
        OnboardingTestDatabase.reset();
        env.put("SPRING_FLYWAY_URL", OnboardingTestDatabase.POSTGRES.getJdbcUrl());
        env.put("SPRING_R2DBC_USERNAME", OnboardingTestDatabase.POSTGRES.getUsername());
        env.put("SPRING_R2DBC_PASSWORD", OnboardingTestDatabase.POSTGRES.getPassword());
        env.put("ISSUER_SIGNING_KMS_REGION", LOCALSTACK.getRegion());
        env.put("ISSUER_SIGNING_KMS_ENDPOINT", LOCALSTACK.getEndpoint().toString());
        env.put("OWN_KEY_AUDIT_SINK", "outbox");
        cli = new OnboardingCli(new OnboardingWiring(CREDENTIALS), new PrintStream(stdout, true, StandardCharsets.UTF_8),
                new PrintStream(stderr, true, StandardCharsets.UTF_8));
    }

    private Path chainFile() throws Exception {
        var certificate = new OwnKeyTestPki().validP256Leaf().certificate();
        String pem = "-----BEGIN CERTIFICATE-----" + (char) 10
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + (char) 10 + "-----END CERTIFICATE-----" + (char) 10;
        return Files.writeString(directory.resolve("chain.pem"), pem);
    }

    @Test
    void prepare_rejectedForAnUnknownTenant_isInTheOutboxWithTheCallerAsActor() throws Exception {
        int exitCode = cli.run(new String[] {"prepare", "--tenant", "nobody", "--cert-chain", chainFile().toString(),
                "--out-dir", directory.resolve("out").toString(), "--non-production"}, env);

        assertThat(exitCode).as(stderr.toString(StandardCharsets.UTF_8)).isEqualTo(OnboardingCli.EXIT_REJECTED);
        assertThat(query("SELECT tenant, event_type, status FROM public.audit_outbox"))
                .singleElement().isEqualTo(List.of("nobody", "SigningConfigurationChanged", "PENDING"));
        String payload = (String) scalar("SELECT payload::text FROM public.audit_outbox");
        assertThat(payload).contains("\"Denied\"", "\"PolicyDenied\"", "arn:aws:iam::");
    }

    @Test
    void reconcile_withTheOutbox_startsAndEndsCleanlyWithoutEvents() {
        execute("DROP TABLE IF EXISTS public.audit_outbox");

        int exitCode = cli.run(new String[] {"reconcile", "--non-production"}, env);

        assertThat(exitCode).as(stderr.toString(StandardCharsets.UTF_8)).isZero();
        assertThat(scalar("SELECT count(*) FROM public.audit_outbox")).isEqualTo(0L);
    }
}
