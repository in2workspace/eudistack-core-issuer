package es.in2.issuer.backend.signing.infrastructure.onboarding;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sun.net.httpserver.HttpServer;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingRejectedException;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class OnboardingWiringTest {

    private static final String ACCOUNT = "123456789012";
    private static final StaticCredentialsProvider CREDENTIALS =
            StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test"));

    private static OnboardingSettings settings(OnboardingSettings.AuditSinkMode mode) {
        return new OnboardingSettings("jdbc:postgresql://127.0.0.1:1/x", "u", "pw", "eu-west-1",
                URI.create("http://127.0.0.1:1"), 7, mode);
    }

    private static OnboardingSettings settingsExpecting(String account, URI sts) {
        return new OnboardingSettings("jdbc:postgresql://127.0.0.1:1/x", "u", "pw", "eu-west-1", sts, 7,
                OnboardingSettings.AuditSinkMode.LOG, null, false, account);
    }

    private static boolean starterIsInThisBuild() {
        try {
            Class.forName(OnboardingWiring.OUTBOX_SINK_FACTORY);
            return true;
        } catch (ClassNotFoundException | NoClassDefFoundError _) {
            return false;
        }
    }

    private static OnboardingWiring wiring() {
        return new OnboardingWiring(CREDENTIALS);
    }

    /** An STS that answers {@code GetCallerIdentity} for {@link #ACCOUNT}. */
    private static HttpServer sts() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        byte[] body = ("<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                + "<GetCallerIdentityResult><Arn>arn:aws:sts::" + ACCOUNT + ":assumed-role/operation/jane</Arn>"
                + "<UserId>AROAEXAMPLE:jane</UserId><Account>" + ACCOUNT + "</Account></GetCallerIdentityResult>"
                + "<ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></GetCallerIdentityResponse>")
                .getBytes(StandardCharsets.UTF_8);
        server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Content-Type", "text/xml");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        return server;
    }

    private static URI uriOf(HttpServer server) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @Test
    void open_logSink_needsNoStarter() {
        try (var services = wiring().open(settings(OnboardingSettings.AuditSinkMode.LOG))) {
            assertThat(services.onboarding()).isNotNull();
        }
    }

    @Test
    void open_outboxSinkInABuildWithoutTheStarter_failsSayingSo() {
        assumeTrue(!starterIsInThisBuild(), "this build includes the audit starter");
        var wiring = wiring();
        var settings = settings(OnboardingSettings.AuditSinkMode.OUTBOX);

        assertThatThrownBy(() -> wiring.open(settings))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("audit starter")
                .hasMessageContaining("-PauditStarter");
    }

    @Test
    void open_expectedAccountThatIsTheCallers_opens() throws Exception {
        HttpServer server = sts();
        try (var services = wiring().open(settingsExpecting(ACCOUNT, uriOf(server)))) {
            assertThat(services.reconciler()).isNotNull();
        } finally {
            server.stop(0);
        }
    }

    @Test
    void open_expectedAccountThatIsNotTheCallers_isRejectedBeforeKmsOrTheDatabaseAreUsed() throws Exception {
        HttpServer server = sts();
        try {
            var wiring = wiring();
            var settings = settingsExpecting("999999999999", uriOf(server));
            // The database URL cannot be reached: reaching the rejection proves nothing was opened before it.
            assertThatThrownBy(() -> wiring.open(settings))
                    .isInstanceOf(OnboardingRejectedException.class)
                    .hasMessageContaining("999999999999")
                    .hasMessageContaining("--expected-aws-account");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void open_expectedAccountThatIsNotTheCallers_logsAWarningWithBothAccounts() throws Exception {
        HttpServer server = sts();
        Logger logger = (Logger) LoggerFactory.getLogger(ExpectedAwsAccount.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            var wiring = wiring();
            var settings = settingsExpecting("999999999999", uriOf(server));

            assertThatThrownBy(() -> wiring.open(settings)).isInstanceOf(OnboardingRejectedException.class);

            assertThat(appender.list).singleElement().satisfies(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getFormattedMessage()).contains(ACCOUNT, "999999999999");
            });
        } finally {
            logger.detachAppender(appender);
            server.stop(0);
        }
    }

    @Test
    void open_expectedAccountWhenTheIdentityCannotBeRead_failsWithAnError() {
        var wiring = wiring();
        var settings = settingsExpecting(ACCOUNT, URI.create("http://127.0.0.1:1"));

        assertThatThrownBy(() -> wiring.open(settings))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("caller identity");
    }

    @Test
    void clients_inProduction_ignoreTheEndpointUrlsConfiguredForTheSdk() {
        String previousEndpoint = System.getProperty("aws.endpointUrl");
        String previousIgnore = System.getProperty(AwsOnboardingClients.IGNORE_CONFIGURED_ENDPOINT_URLS);
        System.setProperty("aws.endpointUrl", "http://127.0.0.1:1");
        System.clearProperty(AwsOnboardingClients.IGNORE_CONFIGURED_ENDPOINT_URLS);
        try (var honoured = AwsOnboardingClients.sts("eu-west-1", null, CREDENTIALS, false)) {
            assertThat(honoured.serviceClientConfiguration().endpointOverride())
                    .as("outside production the configured URL applies").isPresent();
            try (var kms = AwsOnboardingClients.kms("eu-west-1", null, CREDENTIALS, true);
                 var sts = AwsOnboardingClients.sts("eu-west-1", null, CREDENTIALS, true)) {
                assertThat(kms.serviceClientConfiguration().endpointOverride()).isEmpty();
                assertThat(sts.serviceClientConfiguration().endpointOverride()).isEmpty();
            }
        } finally {
            restore("aws.endpointUrl", previousEndpoint);
            restore(AwsOnboardingClients.IGNORE_CONFIGURED_ENDPOINT_URLS, previousIgnore);
        }
    }

    private static void restore(String property, String previous) {
        if (previous == null) {
            System.clearProperty(property);
        } else {
            System.setProperty(property, previous);
        }
    }
}
