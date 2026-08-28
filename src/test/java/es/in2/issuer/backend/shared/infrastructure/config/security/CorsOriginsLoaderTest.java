package es.in2.issuer.backend.shared.infrastructure.config.security;

import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CorsOriginsLoaderTest {

    @Test
    void loadOrigins_ClasspathFileEmpty_ReturnsEmptyList() {
        // The classpath cors-origins.yaml has origins: [] (empty by default)
        CorsOriginsLoader loader = new CorsOriginsLoader(new CorsProperties(null));

        List<String> origins = loader.loadOrigins();

        assertThat(origins).isEmpty();
    }

    @Test
    void loadOrigins_ExternalFileExists_ReadsFromExternalFile(@TempDir Path tempDir) throws IOException {
        Path yamlFile = tempDir.resolve("cors-origins.yaml");
        Files.writeString(yamlFile, """
                origins:
                  - url: "https://external-issuer.example.com"
                    tenant: "test"
                """);

        CorsOriginsLoader loader = new CorsOriginsLoader(new CorsProperties(yamlFile.toString()));

        List<String> origins = loader.loadOrigins();

        assertThat(origins).containsExactly("https://external-issuer.example.com");
    }

    @Test
    void loadOrigins_ExternalFileWithMultipleOrigins_ReturnsAll(@TempDir Path tempDir) throws IOException {
        Path yamlFile = tempDir.resolve("cors-origins.yaml");
        Files.writeString(yamlFile, """
                origins:
                  - url: "https://issuer-core-stg.api.altia.eudistack.net"
                    tenant: "altia"
                  - url: "https://login-stg.altia.eudistack.net"
                    tenant: "altia"
                  - url: "https://verifier-stg.altia.eudistack.net"
                    tenant: "altia"
                """);

        CorsOriginsLoader loader = new CorsOriginsLoader(new CorsProperties(yamlFile.toString()));

        List<String> origins = loader.loadOrigins();

        assertThat(origins).containsExactly(
                "https://issuer-core-stg.api.altia.eudistack.net",
                "https://login-stg.altia.eudistack.net",
                "https://verifier-stg.altia.eudistack.net"
        );
    }

    @Test
    void loadOrigins_ExternalFileNotFound_FallsBackToClasspath(@TempDir Path tempDir) {
        String nonExistentPath = tempDir.resolve("nonexistent.yaml").toString();
        CorsOriginsLoader loader = new CorsOriginsLoader(new CorsProperties(nonExistentPath));

        List<String> origins = loader.loadOrigins();

        // Falls back to classpath cors-origins.yaml which has origins: []
        assertThat(origins).isEmpty();
    }

    @Test
    void loadOrigins_EmptyOriginsList_ReturnsEmptyList(@TempDir Path tempDir) throws IOException {
        Path yamlFile = tempDir.resolve("cors-origins.yaml");
        Files.writeString(yamlFile, "origins: []\n");

        CorsOriginsLoader loader = new CorsOriginsLoader(new CorsProperties(yamlFile.toString()));

        List<String> origins = loader.loadOrigins();

        assertThat(origins).isEmpty();
    }

    @Test
    void loadOrigins_NullOriginsPath_FallsBackToClasspath() {
        CorsOriginsLoader loader = new CorsOriginsLoader(new CorsProperties(null));

        List<String> origins = loader.loadOrigins();

        // Classpath default has origins: []
        assertThat(origins).isEmpty();
    }
}
