package es.in2.issuer.backend.shared.infrastructure.config.tenantconfig;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.DefaultResourceLoader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class TenantCustomDomainsLoaderTest {

    @TempDir
    Path tempDir;

    private TenantCustomDomainsLoader loaderFrom(String yaml) throws IOException {
        Path file = tempDir.resolve("tenants-custom-domains.yaml");
        Files.writeString(file, yaml);
        TenantCustomDomainsLoader loader = new TenantCustomDomainsLoader(
                new DefaultResourceLoader(), "file:" + file.toAbsolutePath());
        loader.load();
        return loader;
    }

    // ── happy path ──────────────────────────────────────────────────────────

    @Test
    void load_parsesTenantsAndIndexesById() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifier: https://kpmg.eudistack.net/verifier
                    wallet: https://kpmg.wallet.eudistack.net
                  - id: acme
                    issuer: https://acme.eudistack.net
                    verifier: https://acme.eudistack.net/verifier
                    wallet: https://acme.wallet.eudistack.net
                """);

        assertEquals("https://kpmg.eudistack.net/verifier", loader.getVerifierUrl("kpmg"));
        assertEquals("https://acme.eudistack.net/verifier", loader.getVerifierUrl("acme"));
    }

    @Test
    void load_emptyTenantsList_doesNotFail() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("tenants:\n");
        assertThrows(IllegalStateException.class, () -> loader.getVerifierUrl("any"));
    }

    // ── missing file ────────────────────────────────────────────────────────

    @Test
    void load_missingFile_doesNotFailStartup() {
        TenantCustomDomainsLoader loader = new TenantCustomDomainsLoader(
                new DefaultResourceLoader(), "file:/nonexistent/tenants-custom-domains.yaml");
        assertDoesNotThrow(loader::load);
    }

    @Test
    void load_missingFile_thenGetVerifierUrl_throws() {
        TenantCustomDomainsLoader loader = new TenantCustomDomainsLoader(
                new DefaultResourceLoader(), "file:/nonexistent/tenants-custom-domains.yaml");
        loader.load();
        assertThrows(IllegalStateException.class, () -> loader.getVerifierUrl("kpmg"));
    }

    // ── unknown tenant ──────────────────────────────────────────────────────

    @Test
    void getVerifierUrl_unknownTenant_throws() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifier: https://kpmg.eudistack.net/verifier
                    wallet: https://kpmg.wallet.eudistack.net
                """);
        assertThrows(IllegalStateException.class, () -> loader.getVerifierUrl("unknown"));
    }

    // ── validation failures (fail at startup) ───────────────────────────────

    @Test
    void load_blankTenantId_throwsAtStartup() {
        assertThrows(IllegalStateException.class, () -> loaderFrom("""
                tenants:
                  - id: ""
                    issuer: https://kpmg.eudistack.net
                    verifier: https://kpmg.eudistack.net/verifier
                    wallet: https://kpmg.wallet.eudistack.net
                """));
    }

    @Test
    void load_blankVerifierUrl_throwsAtStartup() {
        assertThrows(IllegalStateException.class, () -> loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifier: ""
                    wallet: https://kpmg.wallet.eudistack.net
                """));
    }

    @Test
    void load_invalidVerifierUrl_throwsAtStartup() {
        assertThrows(IllegalStateException.class, () -> loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifier: "not a valid uri with spaces here"
                    wallet: https://kpmg.wallet.eudistack.net
                """));
    }
}
