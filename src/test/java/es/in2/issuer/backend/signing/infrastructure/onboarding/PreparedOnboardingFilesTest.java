package es.in2.issuer.backend.signing.infrastructure.onboarding;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.PreparedOnboarding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PreparedOnboardingFilesTest {

    private static final PreparedOnboarding PREPARED = new PreparedOnboarding("0f0e0d0c-0000-4000-8000-000000000001", "cgcom",
            "arn:aws:kms:eu-west-1:000000000000:key/abc", "alias/own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001", List.of("AAAA", "BBBB"),
            "ab".repeat(32), Instant.parse("2026-10-27T12:00:00Z"), Instant.parse("2026-10-28T12:00:00Z"));

    @TempDir
    Path directory;

    @Test
    void write_thenRead_returnsTheSameStateAndTokenWithoutNamingTheTokenFile() {
        new PreparedOnboardingFiles(directory.resolve("out")).write(PREPARED, new byte[] {1, 2, 3}, new byte[] {7, 8});

        var loaded = PreparedOnboardingFiles.read(directory.resolve("out/own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json"), null);

        assertThat(loaded.prepared()).isEqualTo(PREPARED);
        assertThat(loaded.importToken()).containsExactly(7, 8);
    }

    @Test
    void write_leavesTheWrappingKeyAsDerAndAsPem() throws Exception {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1, 2, 3}, new byte[] {7, 8});

        assertThat(Files.readAllBytes(directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.wrapping-public-key.der")))
                .containsExactly(1, 2, 3);
        assertThat(Files.readString(directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.wrapping-public-key.pem"),
                StandardCharsets.US_ASCII))
                .isEqualTo("-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n");
    }

    @Test
    void write_stateFile_holdsNoSecretField() throws Exception {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1, 2, 3}, new byte[] {7, 8});

        assertThat(Files.readString(directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json")))
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

        var loaded = PreparedOnboardingFiles.read(directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json"), token);

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
        var missing = directory.resolve("missing.json");

        assertThatThrownBy(() -> PreparedOnboardingFiles.read(missing, null))
                .isInstanceOf(OnboardingFailedException.class);
    }

    @Test
    void write_renewal_leavesOnlyTheStateFileAndReadsBackWithoutAToken() throws Exception {
        var renewal = new PreparedOnboarding("0f0e0d0c-0000-4000-8000-000000000002", "cgcom", "arn:aws:kms:eu-west-1:000000000000:key/abc", null,
                List.of("AAAA"), "ab".repeat(32), Instant.parse("2026-10-27T12:00:00Z"), null, true, null);

        new PreparedOnboardingFiles(directory).write(renewal, null, null);

        try (var files = Files.list(directory)) {
            assertThat(files.map(path -> path.getFileName().toString())).containsExactly("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000002.state.json");
        }
        var loaded = PreparedOnboardingFiles.read(directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000002.state.json"), null);
        assertThat(loaded.prepared()).isEqualTo(renewal);
        assertThat(loaded.importToken()).isNull();
    }

    @Test
    void markDiscarded_rewritesTheStateFileThatWasGivenWithTheDate() {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1}, new byte[] {2});
        Path state = directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json");
        Instant when = Instant.parse("2026-10-27T13:00:00Z");

        PreparedOnboardingFiles.around(state).markDiscarded(PREPARED, when);

        assertThat(PreparedOnboardingFiles.read(state, null).prepared().discardedAt()).isEqualTo(when);
    }

    @Test
    void markImported_rewritesTheStateWithTheDateAndKeepsTheRest() {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1}, new byte[] {2});
        Path state = directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json");
        Instant when = Instant.parse("2026-10-27T13:00:00Z");

        PreparedOnboardingFiles.around(state).markImported(PREPARED, when);

        var read = PreparedOnboardingFiles.read(state, null).prepared();
        assertThat(read.importedAt()).isEqualTo(when);
        assertThat(read.keyArn()).isEqualTo(PREPARED.keyArn());
        assertThat(read.discardedAt()).isNull();
    }

    @Test
    void current_readsTheMarksAnotherRunLeftSinceTheStateWasRead() {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1}, new byte[] {2});
        Path state = directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json");
        var readBefore = PreparedOnboardingFiles.read(state, null).prepared();
        Instant when = Instant.parse("2026-10-27T13:00:00Z");
        PreparedOnboardingFiles.around(state).markImported(readBefore, when);

        var current = PreparedOnboardingFiles.around(state).current(readBefore);

        assertThat(readBefore.importedAt()).isNull();
        assertThat(current.importedAt()).isEqualTo(when);
        assertThat(current.operationId()).isEqualTo(PREPARED.operationId());
    }

    @ParameterizedTest
    @ValueSource(strings = {"op-of-another-tenant", "0F0E0D0C-0000-4000-8000-000000000001",
            "0f0e0d0c-0000-4000-8000-000000000001\r\nforged log line", ""})
    void read_stateWhoseOperationIdIsNotACanonicalUuid_isRefused(String operationId) throws Exception {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1}, new byte[] {2});
        Path state = directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json");
        String json = Files.readString(state);
        Files.writeString(state, json.replace("\"" + PREPARED.operationId() + "\"",
                new ObjectMapper().writeValueAsString(operationId)));

        assertThatThrownBy(() -> PreparedOnboardingFiles.read(state, null))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("operation id");
    }

    @Test
    void current_ofAStateThatIsNoLongerThere_fails() throws Exception {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1}, new byte[] {2});
        Path state = directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json");
        Files.delete(state);
        var files = PreparedOnboardingFiles.around(state);

        assertThatThrownBy(() -> files.current(PREPARED))
                .isInstanceOf(OnboardingFailedException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"../secret.bin", "/etc/hostname", "sub/own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.import-token.bin",
            "other.bin", "own-key-kpmg-0f0e0d0c-0000-4000-8000-000000000001.import-token.bin"})
    void read_stateNamingATokenFileThatIsNotAPlainNameOfThisPreparation_isRefusedAndNotRead(String tokenFile)
            throws Exception {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1}, new byte[] {2});
        Path state = directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json");
        Files.writeString(state, Files.readString(state).replace("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.import-token.bin", tokenFile));

        assertThatThrownBy(() -> PreparedOnboardingFiles.read(state, null))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("not a file of this preparation");
    }

    @Test
    void write_onAPosixFileSystem_createsAPrivateDirectoryAndPrivateFiles() throws Exception {
        assumeTrue(directory.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path out = directory.resolve("out");

        new PreparedOnboardingFiles(out).write(PREPARED, new byte[] {1}, new byte[] {2});

        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(out))).isEqualTo("rwx------");
        try (var files = Files.list(out)) {
            assertThat(files.map(path -> {
                try {
                    return PosixFilePermissions.toString(Files.getPosixFilePermissions(path));
                } catch (java.io.IOException e) {
                    throw new IllegalStateException(e);
                }
            })).hasSize(4).containsOnly("rw-------");
        }
    }

    @Test
    void markImported_onAPosixFileSystem_keepsTheStateFilePrivateAndLeavesNoTemporaryFile() throws Exception {
        new PreparedOnboardingFiles(directory).write(PREPARED, new byte[] {1}, new byte[] {2});
        Path state = directory.resolve("own-key-cgcom-0f0e0d0c-0000-4000-8000-000000000001.state.json");

        PreparedOnboardingFiles.around(state).markImported(PREPARED, Instant.parse("2026-10-27T13:00:00Z"));

        if (directory.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(state))).isEqualTo("rw-------");
        }
        try (var files = Files.list(directory)) {
            assertThat(files.map(path -> path.getFileName().toString())).noneMatch(name -> name.endsWith(".tmp"));
        }
    }
}
