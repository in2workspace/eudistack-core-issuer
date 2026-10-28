package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OwnKeyOnboarding.ImportCommand;
import es.in2.issuer.backend.signing.domain.spi.KmsKeyAdministrationPort.ImportParameters;
import es.in2.issuer.backend.signing.infrastructure.onboarding.PreparedOnboardingFiles.Loaded;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** The records that carry bytes compare them by content and never print them. */
class OnboardingRecordsWithBytesTest {

    private static final Instant WHEN = Instant.parse("2026-10-28T12:00:00Z");
    private static final PreparedOnboarding PREPARED = new PreparedOnboarding("op-1", "cgcom", "arn:key", null,
            List.of("MIIB"), "ab", WHEN, WHEN);

    @Test
    void importCommand_withEqualBytes_isEqualAndPrintsOnlyTheirLength() {
        var one = new ImportCommand(PREPARED, new byte[] {1, 2}, new byte[] {7, 7, 7}, OnboardingPolicy.nonProduction(),
                false);
        var same = new ImportCommand(PREPARED, new byte[] {1, 2}, new byte[] {7, 7, 7}, OnboardingPolicy.nonProduction(),
                false);

        assertThat(one).isEqualTo(same).hasSameHashCodeAs(same)
                .isNotEqualTo(new ImportCommand(PREPARED, new byte[] {1, 2}, new byte[] {8},
                        OnboardingPolicy.nonProduction(), false));
        assertThat(one.toString()).contains("importToken=2 bytes", "encryptedKeyMaterial=3 bytes")
                .doesNotContain("[B@");
    }

    @Test
    void importParameters_withEqualBytes_isEqualAndPrintsOnlyTheirLength() {
        var one = new ImportParameters(new byte[] {1}, new byte[] {2, 3}, WHEN);
        var same = new ImportParameters(new byte[] {1}, new byte[] {2, 3}, WHEN);

        assertThat(one).isEqualTo(same).hasSameHashCodeAs(same)
                .isNotEqualTo(new ImportParameters(new byte[] {1}, new byte[] {9}, WHEN));
        assertThat(one.toString()).contains("importToken=2 bytes").doesNotContain("[B@");
    }

    @Test
    void loaded_withEqualToken_isEqualAndPrintsOnlyItsLength() {
        var one = new Loaded(PREPARED, new byte[] {4, 5, 6});
        var same = new Loaded(PREPARED, new byte[] {4, 5, 6});

        assertThat(one).isEqualTo(same).hasSameHashCodeAs(same)
                .isNotEqualTo(new Loaded(PREPARED, null));
        assertThat(one.toString()).contains("importToken=3 bytes").doesNotContain("[B@");
    }
}
