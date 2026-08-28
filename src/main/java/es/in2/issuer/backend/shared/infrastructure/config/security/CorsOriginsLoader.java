package es.in2.issuer.backend.shared.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

/**
 * Loads CORS allowed origins from a YAML file.
 * Supports external filesystem path (for Docker/K8s mounts) with classpath fallback.
 */
@Slf4j
@Component
public class CorsOriginsLoader {

    private static final String CLASSPATH_DEFAULT = "cors-origins.yaml";
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private final String externalPath;

    public CorsOriginsLoader(CorsProperties corsProperties) {
        this.externalPath = corsProperties != null ? corsProperties.originsPath() : null;
    }

    public List<String> loadOrigins() {
        try (InputStream is = openInputStream()) {
            if (is == null) {
                log.info("No cors-origins.yaml found — using only base origins from application.yml");
                return Collections.emptyList();
            }
            CorsOriginsData data = yamlMapper.readValue(is, CorsOriginsData.class);
            if (data.getOrigins() == null || data.getOrigins().isEmpty()) {
                return Collections.emptyList();
            }
            List<String> origins = data.getOrigins().stream()
                    .map(CorsOriginsData.OriginEntry::getUrl)
                    .filter(url -> url != null && !url.isBlank())
                    .toList();
            log.info("Loaded {} CORS origins from cors-origins.yaml", origins.size());
            return origins;
        } catch (IOException e) {
            log.warn("Failed to read cors-origins.yaml — using only base origins: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    private InputStream openInputStream() throws IOException {
        if (externalPath != null && !externalPath.isBlank()) {
            Path path = Path.of(externalPath);
            if (Files.exists(path)) {
                log.info("Loading CORS origins from external file: {}", externalPath);
                return new FileInputStream(path.toFile());
            }
            log.warn("External CORS origins file not found: {}. Falling back to classpath.", externalPath);
        }
        InputStream is = getClass().getClassLoader().getResourceAsStream(CLASSPATH_DEFAULT);
        if (is != null) {
            log.info("Loading CORS origins from classpath: {}", CLASSPATH_DEFAULT);
        }
        return is;
    }
}
