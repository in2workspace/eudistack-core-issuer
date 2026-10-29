package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.issuer.backend.shared.domain.model.port.AuthorizationMatrixProvider;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Loads the issuer action matrix (FR-15) from an external YAML file, or from the copy bundled in
 * the classpath when no file is configured. The external file is checked every
 * {@value #CHECK_INTERVAL_MS} ms by a scheduled task -- never on the request path, so the event loop
 * does no file I/O -- and a change applies to the next request without restarting.
 *
 * <p>A change is detected by the content's SHA-256, not by the modification time: a file read while
 * it was being written is rejected, and the finished one (same mtime on a coarse filesystem) is
 * still picked up because its content differs.
 *
 * <p>A configured file that is missing, unreadable or invalid fails startup: falling back to the
 * bundled rules would silently relax a hardened deployment. A later change that does not parse or
 * validate is rejected and the last valid matrix stays in force, so a broken edit never leaves the
 * issuer without rules and never opens anything. Every load and rejection is audited with the
 * matrix version and digest (conv-quality-security-gates §3.4: policy changes are versioned and
 * audited).
 */
@Slf4j
@Component
public class FileAuthorizationMatrixProvider implements AuthorizationMatrixProvider {

    static final String CLASSPATH_DEFAULT = "authorization/authorization-matrix.yaml";
    static final long CHECK_INTERVAL_MS = 2000;
    static final String EVENT_LOADED = "authorization.policy.loaded";
    static final String EVENT_REJECTED = "authorization.policy.rejected";

    private static final String MISSING = "missing";
    private static final String ACTOR = "system";
    private static final String RESOURCE_TYPE = "authorization_matrix";

    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory())
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    private final Path externalPath;
    private final AuditService auditService;

    private final AtomicReference<AuthorizationMatrix> matrix = new AtomicReference<>();
    /** Digest of the last content seen, applied or rejected, so a rejected file is not re-reported. */
    private volatile String lastSeenDigest;

    public FileAuthorizationMatrixProvider(@Value("${app.authorization.matrix-path:}") String matrixPath,
                                           AuditService auditService) {
        this.externalPath = matrixPath == null || matrixPath.isBlank() ? null : Path.of(matrixPath);
        this.auditService = auditService;
        this.matrix.set(externalPath != null ? loadExternal() : loadBundled());
    }

    @Override
    public AuthorizationMatrix current() {
        return matrix.get();
    }

    @Scheduled(fixedDelay = CHECK_INTERVAL_MS, initialDelay = CHECK_INTERVAL_MS)
    public void reloadIfChanged() {
        if (externalPath == null) {
            return;
        }
        byte[] content;
        try {
            content = Files.readAllBytes(externalPath);
        } catch (IOException e) {
            if (!MISSING.equals(lastSeenDigest)) {
                lastSeenDigest = MISSING;
                reject("unreadable", null, e);
            }
            return;
        }
        String digest = sha256(content);
        if (digest.equals(lastSeenDigest)) {
            return;
        }
        lastSeenDigest = digest;
        try {
            AuthorizationMatrix reloaded = parse(content);
            matrix.set(reloaded);
            loaded(reloaded, digest, "Reloaded");
        } catch (IOException | RuntimeException e) {
            reject("invalid", digest, e);
        }
    }

    private AuthorizationMatrix loadExternal() {
        try {
            byte[] content = Files.readAllBytes(externalPath);
            String digest = sha256(content);
            AuthorizationMatrix loaded = parse(content);
            lastSeenDigest = digest;
            loaded(loaded, digest, "Loaded");
            return loaded;
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("Cannot load the configured authorization matrix " + externalPath, e);
        }
    }

    private AuthorizationMatrix loadBundled() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(CLASSPATH_DEFAULT)) {
            if (is == null) {
                throw new IllegalStateException("Bundled authorization matrix not found: " + CLASSPATH_DEFAULT);
            }
            byte[] content = is.readAllBytes();
            AuthorizationMatrix loaded = parse(content);
            loaded(loaded, sha256(content), "Loaded bundled");
            return loaded;
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read bundled authorization matrix", e);
        }
    }

    private AuthorizationMatrix parse(byte[] content) throws IOException {
        return yamlMapper.readValue(content, AuthorizationMatrix.class)
                .validate(PowerAuthorizationService.ACTIONS_IN_USE);
    }

    private void loaded(AuthorizationMatrix loaded, String digest, String verb) {
        String source = externalPath != null ? externalPath.toString() : "classpath:" + CLASSPATH_DEFAULT;
        log.info("{} authorization matrix v{} from {} (sha256 {})", verb, loaded.version(), source, digest);
        try {
            auditService.auditSuccess(EVENT_LOADED, ACTOR, RESOURCE_TYPE, source,
                    Map.of("version", loaded.version(), "sha256", digest));
        } catch (RuntimeException e) {
            log.warn("Failed to audit the authorization matrix load: {}", e.toString());
        }
    }

    private void reject(String reason, String digest, Exception cause) {
        log.error("Rejected change to authorization matrix {}; keeping the previous rules: {}",
                externalPath, cause.getMessage());
        try {
            auditService.auditFailure(EVENT_REJECTED, ACTOR, reason,
                    digest != null ? Map.of("source", externalPath.toString(), "sha256", digest)
                            : Map.of("source", externalPath.toString()));
        } catch (RuntimeException e) {
            log.warn("Failed to audit the authorization matrix rejection: {}", e.toString());
        }
    }

    private static String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
