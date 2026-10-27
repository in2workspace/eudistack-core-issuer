package es.in2.issuer.backend.signing.infrastructure.onboarding;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import es.in2.issuer.backend.signing.domain.onboarding.PreparedOnboarding;
import es.in2.issuer.backend.signing.domain.spi.OnboardingArtifactsPort;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

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
 * <p>No file is ever overwritten, except the state file, which {@code discard} marks. A renewal leaves only the
 * state file: there is no wrapping key and no token.
 */
public class PreparedOnboardingFiles implements OnboardingArtifactsPort {

    private static final int STATE_VERSION = 1;
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
    public record Loaded(PreparedOnboarding prepared, byte[] importToken) {}

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
            Instant discardedAt
    ) {}

    @Override
    public void write(PreparedOnboarding prepared, byte[] wrappingPublicKeyDer, byte[] importToken) {
        String prefix = prefix(prepared);
        String tokenFile = prepared.renewal() ? null : prefix + ".import-token.bin";
        try {
            Files.createDirectories(outputDirectory);
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

    /** Rewrites the state file next to the others with {@code discardedAt}; this is the one file that is overwritten. */
    @Override
    public void markDiscarded(PreparedOnboarding prepared, Instant discardedAt) {
        String prefix = prefix(prepared);
        try {
            Files.write(stateFile != null ? stateFile : outputDirectory.resolve(prefix + ".state.json"),
                    MAPPER.writeValueAsBytes(document(
                    new PreparedOnboarding(prepared.operationId(), prepared.tenant(), prepared.keyArn(), prepared.alias(),
                            prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                            prepared.importTokenExpiresAt(), prepared.renewal(), discardedAt),
                    prepared.renewal() ? null : prefix + ".import-token.bin")));
        } catch (IOException e) {
            throw new OnboardingFailedException("could not mark the state file as discarded", e);
        }
    }

    private static String prefix(PreparedOnboarding prepared) {
        return "own-key-" + prepared.tenant() + "-" + prepared.operationId();
    }

    private static StateDocument document(PreparedOnboarding prepared, String tokenFile) {
        return new StateDocument(STATE_VERSION, prepared.operationId(), prepared.tenant(), prepared.keyArn(),
                prepared.alias(), prepared.certificateChain(), prepared.spkiSha256(), prepared.createdAt(),
                prepared.importTokenExpiresAt(), tokenFile, prepared.renewal(), prepared.discardedAt());
    }

    /**
     * @param importTokenFile the token file; {@code null} takes the one named in the state, next to it. The token
     *                        of a renewal is {@code null}: there is none.
     */
    public static Loaded read(Path stateFile, Path importTokenFile) {
        try {
            StateDocument state = MAPPER.readValue(Files.readAllBytes(stateFile), StateDocument.class);
            if (state.version() != STATE_VERSION) {
                throw new OnboardingFailedException("unsupported state file version " + state.version());
            }
            byte[] token = null;
            if (!state.renewal() && state.importTokenFile() != null) {
                Path tokenPath = importTokenFile != null ? importTokenFile
                        : stateFile.toAbsolutePath().resolveSibling(state.importTokenFile());
                token = readTokenUnlessDiscarded(tokenPath, state);
            }
            return new Loaded(new PreparedOnboarding(state.operationId(), state.tenant(), state.keyArn(), state.alias(),
                    state.certificateChain(), state.spkiSha256(), state.createdAt(), state.importTokenExpiresAt(),
                    state.renewal(), state.discardedAt()), token);
        } catch (JsonProcessingException e) {
            throw new OnboardingFailedException("the state file " + stateFile + " is not a valid state file");
        } catch (IOException e) {
            throw new OnboardingFailedException("could not read " + stateFile + " or its import token", e);
        }
    }

    /** A discarded preparation is still readable (to refuse it by name) even if its token file was removed. */
    private static byte[] readTokenUnlessDiscarded(Path tokenPath, StateDocument state) throws IOException {
        return state.discardedAt() != null && !Files.exists(tokenPath) ? new byte[0] : Files.readAllBytes(tokenPath);
    }

    private static void create(Path file, byte[] content) throws IOException {
        Files.write(file, content, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    private static byte[] pem(byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return ("-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n").getBytes(StandardCharsets.US_ASCII);
    }
}
