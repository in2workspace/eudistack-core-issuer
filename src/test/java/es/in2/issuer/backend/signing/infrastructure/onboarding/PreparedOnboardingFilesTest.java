package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.PreparedOnboarding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PreparedOnboardingFilesTest {

    private static final PreparedOnboarding PREPARED = new PreparedOnboarding("op-1", "cgcom",
            "arn:aws:kms:eu-west-1:000000000000:key/abc", "alias/own-key-cgcom-op-1", List.of("AAAA", "BBBB"),
            "ab".repeat(32), Instant.parse("2026-10-27T12:00:00Z"), Instant.parse("2026-10-28T12:00:00Z"));

    @TempDir
    Path directory;

    @Test
    void write_thenRead_returnsTheSameStateAndTokenWithoutNamingTheTokenFile() {
        new PreparedOnboardingFiles(directory.resolve("out")).write(PREPARED, new byte[] {1, 2, 3}, new byte[] {7, 8});

        var loaded = PreparedOnboardingFiles.read(directory.resolve("out/own-key-cgcom-op-1.state.json"), null);

        assertThat(loaded.prepared()).isEqualTo(PREPARED);
        assertThat(loaded.importToken()).containsExactly(7, 8);
    }

    @Test
    void write_leavesTheWrappingKeyAsDerAndAsPem() throws Exception {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1, 2, 3}, new byte[] {7, 8});

        assertThat(Files.readAllBytes(directory.resolve("own-key-cgcom-op-1.wrapping-public-key.der")))
                .containsExactly(1, 2, 3);
        assertThat(Files.readString(directory.resolve("own-key-cgcom-op-1.wrapping-public-key.pem"),
                StandardCharsets.US_ASCII))
                .isEqualTo("-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n");
    }

    @Test
    void write_stateFile_holdsNoSecretField() throws Exception {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1, 2, 3}, new byte[] {7, 8});

        assertThat(Files.readString(directory.resolve("own-key-cgcom-op-1.state.json")))
                .doesNotContainIgnoringCase("private").doesNotContainIgnoringCase("password")
                .doesNotContainIgnoringCase("secret");
    }

    @Test
    void write_neverOverwritesAnExistingFile() {
        var files = new PreparedOnboardingFiles(directory);
        files.write(PREPARED, new byte[] {1}, new byte[] {2});

        assertThatThrownBy(() -> files.write(PREPARED, new byte[] {1}, new byte[] {2}))
                .isInstanceOf(OnboardingFailedException.class);
    }

    @Test
    void read_importTokenGivenExplicitly_usesIt() throws Exception {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1}, new byte[] {2});
        Path token = Files.write(directory.resolve("other.bin"), new byte[] {5});

        var loaded = PreparedOnboardingFiles.read(directory.resolve("own-key-cgcom-op-1.state.json"), token);

        assertThat(loaded.importToken()).containsExactly(5);
    }

    @Test
    void read_fileThatIsNotAStateFile_fails() throws Exception {
        Path notState = Files.writeString(directory.resolve("state.json"), "not json");

        assertThatThrownBy(() -> PreparedOnboardingFiles.read(notState, null))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("not a valid state file");
    }

    @Test
    void read_missingFile_fails() {
        assertThatThrownBy(() -> PreparedOnboardingFiles.read(directory.resolve("missing.json"), null))
                .isInstanceOf(OnboardingFailedException.class);
    }
}
