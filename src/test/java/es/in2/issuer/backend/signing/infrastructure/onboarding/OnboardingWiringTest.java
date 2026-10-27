package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class OnboardingWiringTest {

    private static OnboardingSettings settings(OnboardingSettings.AuditSinkMode mode) {
        return new OnboardingSettings("jdbc:postgresql://127.0.0.1:1/x", "u", "pw", "eu-west-1",
                URI.create("http://127.0.0.1:1"), 7, mode);
    }

    private static boolean starterIsInThisBuild() {
        try {
            Class.forName(OnboardingWiring.OUTBOX_SINK_FACTORY);
            return true;
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            return false;
        }
    }

    private static OnboardingWiring wiring() {
        return new OnboardingWiring(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")));
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

        assertThatThrownBy(() -> wiring().open(settings(OnboardingSettings.AuditSinkMode.OUTBOX)))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("audit starter")
                .hasMessageContaining("-PauditStarter");
    }
}
