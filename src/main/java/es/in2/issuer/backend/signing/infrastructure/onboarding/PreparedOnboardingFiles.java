package es.in2.issuer.backend.signing.infrastructure.onboarding;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.PolicySummary;
import es.in2.issuer.backend.signing.domain.onboarding.PreparedOnboarding;
import es.in2.issuer.backend.signing.domain.spi.OnboardingArtifactsPort;
import es.in2.issuer.backend.signing.domain.util.KeyRefs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * The files {@code prepare} leaves in the output directory, and how {@code import} reads them back. For an
 * onboarding {@code own-key-<tenant>-<operationId>}:
 *
 * <ul>
 *   <li>{@code .wrapping-public-key.der} and {@code .wrapping-public-key.pem}: what the customer wraps its key with;</li>
 *   <li>{@code .import-token.bin}: the token that goes with the wrapped key material;</li>
 *   <li>{@code .state.json}: the {@link PreparedOnboarding}, without secrets.</li>
 * </ul>
 *
 * <p>No file is ever overwritten, except the state file, which {@code discard} and {@code import} mark: it is
 * rewritten through a temporary file and an atomic move, so a failure never leaves it half written. A renewal leaves
 * only the state file: there is no wrapping key and no token. Where the file system is POSIX, the directory this
 * creates is {@code 0700} and every file {@code 0600}; elsewhere (Windows) the defaults of the file system apply.
 */
public class PreparedOnboardingFiles implements OnboardingArtifactsPort {

    private static final int STATE_VERSION = 1;
    private static final FileAttribute<?> OWNER_ONLY_FILE = PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rw-------"));
    private static final FileAttribute<?> OWNER_ONLY_DIRECTORY = PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------"));
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE)
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final Path outputDirectory;
    /** The state file {@link #markDiscarded} rewrites; {@code null} derives its name from the preparation. */
    private final Path stateFile;

    public PreparedOnboardingFiles(Path outputDirectory) {
        this(outputDirectory, null);
    }

    /** Files around an existing state file, which is the one {@link #markDiscarded} rewrites. */
    public static PreparedOnboardingFiles around(Path stateFile) {
        return new PreparedOnboardingFiles(stateFile.toAbsolutePath().getParent(), stateFile);
    }

    private PreparedOnboardingFiles(Path outputDirectory, Path stateFile) {
        this.outputDirectory = outputDirectory;
        this.stateFile = stateFile;
    }

    /** What {@code import} needs from the files: the state and the token ({@code null} on a renewal). */
    public record Loaded(PreparedOnboarding prepared, byte[] importToken) {

        @Override
        public boolean equals(Object other) {
            return other instanceof Loaded(var otherPrepared, var otherToken)
                    && Objects.equals(prepared, otherPrepared) && Arrays.equals(importToken, otherToken);
        }

        @Override
        public int hashCode() {
            return Objects.hash(prepared, Arrays.hashCode(importToken));
        }

        /** The token is never printed, only its length. */
        @Override
        public String toString() {
            return "Loaded[prepared=" + prepared + ", importToken="
                    + (importToken == null ? "null" : importToken.length + " bytes") + "]";
        }
    }

    /** The JSON of the state file: the state plus the name of the token file next to it. */
    private record StateDocument(
            int version,
            String operationId,
            String tenant,
            String keyArn,
            String alias,
            List<String> certificateChain,
            String spkiSha256,
            Instant createdAt,
            Instant importTokenExpiresAt,
            String importTokenFile,
            boolean renewal,
            Instant discardedAt,
            Instant importedAt,
            PolicySummary policy
    ) {}

    @Override
    public void write(PreparedOnboarding prepared, byte[] wrappingPublicKeyDer, byte[] importToken) {
        String prefix = prefix(prepared);
        String tokenFile = prepared.renewal() ? null : prefix + ".import-token.bin";
        try {
            createDirectories(outputDirectory);
            if (!prepared.renewal()) {
                create(outputDirectory.resolve(prefix + ".wrapping-public-key.der"), wrappingPublicKeyDer);
                create(outputDirectory.resolve(prefix + ".wrapping-public-key.pem"), pem(wrappingPublicKeyDer));
                create(outputDirectory.resolve(tokenFile), importToken);
            }
            create(outputDirectory.resolve(prefix + ".state.json"), MAPPER.writeValueAsBytes(document(prepared, tokenFile)));
        } catch (IOException e) {
            throw new OnboardingFailedException("could not write the onboarding files to " + outputDirectory, e);
        }
    }

    /** Rewrites the state file with {@code discardedAt}: one of the two files that are overwritten, in place. */
    @Override
    public void markDiscarded(PreparedOnboarding prepared, Instant discardedAt) {
        rewrite(new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(), prepared.alias(),
                prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                prepared.importTokenExpiresAt(), prepared.renewal(), discardedAt, prepared.importedAt(), prepared.policy()));
    }

    /** Rewrites the state file with {@code importedAt}: a consumed state is refused by {@code import}. */
    @Override
    public void markImported(PreparedOnboarding prepared, Instant importedAt) {
        rewrite(new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(), prepared.alias(),
                prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                prepared.importTokenExpiresAt(), prepared.renewal(), prepared.discardedAt(), importedAt, prepared.policy()));
    }

    /** Reads the state file again; the import token is not read, only the marks matter here. */
    @Override
    public PreparedOnboarding current(PreparedOnboarding prepared) {
        Path file = stateFileOf(prepared);
        try {
            return prepared(readState(file));
        } catch (JsonProcessingException _) {
            throw new OnboardingFailedException("the state file " + file + " is not a valid state file");
        } catch (IOException e) {
            throw new OnboardingFailedException("could not read " + file + " again", e);
        }
    }

    private Path stateFileOf(PreparedOnboarding prepared) {
        return stateFile != null ? stateFile : outputDirectory.resolve(prefix(prepared) + ".state.json");
    }

    private void rewrite(PreparedOnboarding marked) {
        String prefix = prefix(marked);
        try {
            replaceAtomically(stateFileOf(marked),
                    MAPPER.writeValueAsBytes(document(marked, marked.renewal() ? null : prefix + ".import-token.bin")));
        } catch (IOException e) {
            throw new OnboardingFailedException("could not mark the state file", e);
        }
    }

    private static String prefix(PreparedOnboarding prepared) {
        return "own-key-" + prepared.tenant() + "-" + prepared.operationId();
    }

    private static StateDocument document(PreparedOnboarding prepared, String tokenFile) {
        return new StateDocument(STATE_VERSION, prepared.operationId(), prepared.tenant(), prepared.keyArn(),
                prepared.alias(), prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                prepared.importTokenExpiresAt(), tokenFile, prepared.renewal(), prepared.discardedAt(), prepared.importedAt(), prepared.policy());
    }

    /**
     * @param importTokenFile the token file; {@code null} takes the one named in the state, next to it. The token
     *                        of a renewal is {@code null}: there is none.
     */
    public static Loaded read(Path stateFile, Path importTokenFile) {
        try {
            StateDocument state = readState(stateFile);
            byte[] token = null;
            if (!state.renewal() && state.importTokenFile() != null) {
                Path tokenPath = importTokenFile != null ? importTokenFile
                        : stateFile.toAbsolutePath().resolveSibling(requireOwnTokenFileName(state));
                token = readTokenUnlessDiscarded(tokenPath, state);
            }
            return new Loaded(prepared(state), token);
        } catch (JsonProcessingException _) {
            throw new OnboardingFailedException("the state file " + stateFile + " is not a valid state file");
        } catch (IOException e) {
            throw new OnboardingFailedException("could not read " + stateFile + " or its import token", e);
        }
    }

    private static StateDocument readState(Path stateFile) throws IOException {
        StateDocument state = MAPPER.readValue(Files.readAllBytes(stateFile), StateDocument.class);
        if (state.version() != STATE_VERSION) {
            throw new OnboardingFailedException("unsupported state file version " + state.version());
        }
        requireCanonicalUuid(state.operationId());
        if (!KeyRefs.isKeyArn(state.keyArn())) {
            throw new OnboardingFailedException("the state file does not name its KMS key by its full ARN: it was not "
                    + "written by prepare, or it was edited");
        }
        return state;
    }

    private static PreparedOnboarding prepared(StateDocument state) {
        return new PreparedOnboarding(state.operationId(), state.tenant(), state.keyArn(), state.alias(),
                state.certificateChain(), state.spkiSha256(), state.createdAt(), state.importTokenExpiresAt(),
                state.renewal(), state.discardedAt(), state.importedAt(), state.policy());
    }

    /**
     * The operation id of a state is the one the tool generated, a canonical UUID: it ends up in the configuration row and
     * as the correlation id of the audit events, so a state edited to carry any other text is refused.
     */
    private static void requireCanonicalUuid(String operationId) {
        boolean canonical;
        try {
            canonical = operationId != null && UUID.fromString(operationId).toString().equals(operationId);
        } catch (IllegalArgumentException _) {
            canonical = false;
        }
        if (!canonical) {
            throw new OnboardingFailedException("the state file does not hold a valid operation id: it was not written "
                    + "by prepare, or it was edited");
        }
    }

    /** A discarded preparation is still readable (to refuse it by name) even if its token file was removed. */
    private static byte[] readTokenUnlessDiscarded(Path tokenPath, StateDocument state) throws IOException {
        return state.discardedAt() != null && !Files.exists(tokenPath) ? new byte[0] : Files.readAllBytes(tokenPath);
    }

    /**
     * The state file is not trusted: the token it names must be a plain file name of this preparation, not a path
     * that sends the tool to read any file and hand it to KMS as a token.
     */
    private static String requireOwnTokenFileName(StateDocument state) {
        String name = state.importTokenFile();
        String prefix = "own-key-" + state.tenant() + "-" + state.operationId();
        if (name.contains("/") || name.contains("\\") || name.contains("..") || !name.startsWith(prefix)
                || !name.equals(Path.of(name).getFileName().toString())) {
            throw new OnboardingFailedException("the state file names an import token file that is not a file of "
                    + "this preparation (own-key-<tenant>-<operationId>...): it is not read");
        }
        return name;
    }

    private static boolean isPosix(Path path) {
        return path.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    /** A new directory is private to the operator; an existing one is the operator's own choice and is left alone. */
    private static void createDirectories(Path directory) throws IOException {
        if (isPosix(directory)) {
            Files.createDirectories(directory, OWNER_ONLY_DIRECTORY);
        } else {
            Files.createDirectories(directory);
        }
    }

    private static void create(Path file, byte[] content) throws IOException {
        if (isPosix(file)) {
            Files.createFile(file, OWNER_ONLY_FILE);
        } else {
            Files.createFile(file);
        }
        Files.write(file, content, StandardOpenOption.WRITE);
    }

    /** Temporary file next to the target, then an atomic move over it: the state is never half written. */
    private static void replaceAtomically(Path target, byte[] content) throws IOException {
        Path directory = target.toAbsolutePath().getParent();
        Path temporary = isPosix(directory) ? Files.createTempFile(directory, ".state-", ".tmp", OWNER_ONLY_FILE)
                : Files.createTempFile(directory, ".state-", ".tmp");
        try {
            Files.write(temporary, content, StandardOpenOption.WRITE);
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException | RuntimeException e) {
            Files.deleteIfExists(temporary);
            throw e;
        }
    }

    private static byte[] pem(byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return ("-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n").getBytes(StandardCharsets.US_ASCII);
    }
}
