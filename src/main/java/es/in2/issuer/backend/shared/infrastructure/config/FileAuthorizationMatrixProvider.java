package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.issuer.backend.shared.domain.model.port.AuthorizationMatrixProvider;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Loads the issuer action matrix (FR-15) from an external YAML file, falling back to the copy
 * bundled in the classpath. The external file is re-read when it changes -- checked at most once per
 * {@link #CHECK_INTERVAL} -- so a rule change applies to the next request without restarting.
 *
 * <p>An unreadable or invalid matrix fails startup. A later change that does not parse or validate
 * is rejected and logged, and the last valid matrix stays in force: a broken edit never leaves the
 * issuer without rules, and never opens anything (every action keeps its previous scope).
 */
@Slf4j
@Component
public class FileAuthorizationMatrixProvider implements AuthorizationMatrixProvider {

    static final String CLASSPATH_DEFAULT = "authorization/authorization-matrix.yaml";
    static final Duration CHECK_INTERVAL = Duration.ofSeconds(2);

    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private final Path externalPath;
    private final Clock clock;

    private volatile AuthorizationMatrix matrix;
    private volatile Instant lastModified = Instant.EPOCH;
    private volatile Instant lastCheck = Instant.EPOCH;

    @Autowired
    public FileAuthorizationMatrixProvider(@Value("${app.authorization.matrix-path:}") String matrixPath) {
        this(matrixPath, Clock.systemUTC());
    }

    FileAuthorizationMatrixProvider(String matrixPath, Clock clock) {
        this.externalPath = matrixPath == null || matrixPath.isBlank() ? null : Path.of(matrixPath);
        this.clock = clock;
        this.matrix = loadInitial();
    }

    @Override
    public AuthorizationMatrix current() {
        if (externalPath != null) {
            reloadIfChanged();
        }
        return matrix;
    }

    private AuthorizationMatrix loadInitial() {
        if (externalPath != null && Files.isRegularFile(externalPath)) {
            try {
                lastModified = Files.getLastModifiedTime(externalPath).toInstant();
                AuthorizationMatrix loaded = readExternal();
                log.info("Loaded authorization matrix v{} from {}", loaded.version(), externalPath);
                return loaded;
            } catch (IOException e) {
                throw new IllegalStateException("Cannot read authorization matrix " + externalPath, e);
            }
        }
        if (externalPath != null) {
            log.warn("Authorization matrix {} not found, using the bundled one", externalPath);
        }
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(CLASSPATH_DEFAULT)) {
            if (is == null) {
                throw new IllegalStateException("Bundled authorization matrix not found: " + CLASSPATH_DEFAULT);
            }
            AuthorizationMatrix loaded = yamlMapper.readValue(is, AuthorizationMatrix.class).validate();
            log.info("Loaded bundled authorization matrix v{}", loaded.version());
            return loaded;
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read bundled authorization matrix", e);
        }
    }

    private void reloadIfChanged() {
        Instant now = clock.instant();
        if (Duration.between(lastCheck, now).compareTo(CHECK_INTERVAL) < 0) {
            return;
        }
        synchronized (this) {
            if (Duration.between(lastCheck, now).compareTo(CHECK_INTERVAL) < 0) {
                return;
            }
            lastCheck = now;
            try {
                if (!Files.isRegularFile(externalPath)) {
                    return;
                }
                Instant modified = Files.getLastModifiedTime(externalPath).toInstant();
                if (modified.equals(lastModified)) {
                    return;
                }
                lastModified = modified;
                AuthorizationMatrix reloaded = readExternal();
                matrix = reloaded;
                log.info("Reloaded authorization matrix v{} from {}", reloaded.version(), externalPath);
            } catch (IOException | RuntimeException e) {
                log.error("Rejected change to authorization matrix {}; keeping the previous rules: {}",
                        externalPath, e.getMessage());
            }
        }
    }

    private AuthorizationMatrix readExternal() throws IOException {
        try (InputStream is = Files.newInputStream(externalPath)) {
            return yamlMapper.readValue(is, AuthorizationMatrix.class).validate();
        }
    }
}
