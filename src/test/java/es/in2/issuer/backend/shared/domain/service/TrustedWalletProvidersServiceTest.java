package es.in2.issuer.backend.shared.domain.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.DefaultResourceLoader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class TrustedWalletProvidersServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void loadProviders_shouldLoadProvidersFromYaml() throws IOException {
        Path yamlFile = tempDir.resolve("providers.yaml");
        Files.writeString(yamlFile, """
                trustedWalletProviders:
                  - id: "dev-wallet-provider"
                    name: "Development Wallet Provider"
                    publicKeyPem: "MFkw..."
                  - id: "test-provider"
                    name: "Test Provider"
                    publicKeyPem: "MIIBoj..."
                """);

        TrustedWalletProvidersService service = new TrustedWalletProvidersService(
                new DefaultResourceLoader(),
                "file:" + yamlFile.toAbsolutePath()
        );
        service.loadProviders();

        assertTrue(service.isWalletProviderTrusted("dev-wallet-provider"));
        assertTrue(service.isWalletProviderTrusted("test-provider"));
        assertFalse(service.isWalletProviderTrusted("unknown-provider"));
        assertEquals(2, service.getAllTrustedProviders().size());
    }

    @Test
    void loadProviders_shouldHandleMissingFile() {
        TrustedWalletProvidersService service = new TrustedWalletProvidersService(
                new DefaultResourceLoader(),
                "file:/nonexistent/path.yaml"
        );

        assertDoesNotThrow(service::loadProviders);
        assertFalse(service.isWalletProviderTrusted("any"));
        assertTrue(service.getAllTrustedProviders().isEmpty());
    }

    @Test
    void isWalletProviderTrusted_shouldReturnFalseForNull() throws IOException {
        Path yamlFile = tempDir.resolve("providers.yaml");
        Files.writeString(yamlFile, """
                trustedWalletProviders:
                  - id: "dev-wallet-provider"
                    name: "Dev"
                """);

        TrustedWalletProvidersService service = new TrustedWalletProvidersService(
                new DefaultResourceLoader(),
                "file:" + yamlFile.toAbsolutePath()
        );
        service.loadProviders();

        assertFalse(service.isWalletProviderTrusted(null));
    }

    @Test
    void loadProviders_shouldHandleEmptyProvidersList() throws IOException {
        Path yamlFile = tempDir.resolve("providers.yaml");
        Files.writeString(yamlFile, "trustedWalletProviders:\n");

        TrustedWalletProvidersService service = new TrustedWalletProvidersService(
                new DefaultResourceLoader(),
                "file:" + yamlFile.toAbsolutePath()
        );

        assertDoesNotThrow(service::loadProviders);
        assertTrue(service.getAllTrustedProviders().isEmpty());
    }
}
