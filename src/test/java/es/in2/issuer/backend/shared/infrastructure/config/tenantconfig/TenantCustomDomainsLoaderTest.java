package es.in2.issuer.backend.shared.infrastructure.config.tenantconfig;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.DefaultResourceLoader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

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
                    verifiers:
                      - https://kpmg.eudistack.net/verifier
                    wallet: https://kpmg.wallet.eudistack.net
                  - id: acme
                    issuer: https://acme.eudistack.net
                    verifiers:
                      - https://acme.eudistack.net/verifier
                    wallet: https://acme.wallet.eudistack.net
                """);

        assertEquals(List.of("https://kpmg.eudistack.net/verifier"), loader.getVerifierUrls("kpmg"));
        assertEquals(List.of("https://acme.eudistack.net/verifier"), loader.getVerifierUrls("acme"));
    }

    @Test
    void load_multipleVerifiersPerTenant_allReturned() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("""
                tenants:
                  - id: dome
                    issuer: https://issuer.dome-marketplace.eu
                    verifiers:
                      - https://verifier.dome-marketplace.eu
                      - https://verifier2.dome-marketplace.eu
                    wallet: https://wallet.dome-marketplace.eu
                """);

        assertEquals(
                List.of("https://verifier.dome-marketplace.eu", "https://verifier2.dome-marketplace.eu"),
                loader.getVerifierUrls("dome"));
    }

    @Test
    void load_emptyTenantsList_doesNotFail() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("tenants:\n");
        assertThrows(IllegalStateException.class, () -> loader.getVerifierUrls("any"));
    }

    // ── missing file ────────────────────────────────────────────────────────

    @Test
    void load_missingFile_doesNotFailStartup() {
        TenantCustomDomainsLoader loader = new TenantCustomDomainsLoader(
                new DefaultResourceLoader(), "file:/nonexistent/tenants-custom-domains.yaml");
        assertDoesNotThrow(loader::load);
    }

    @Test
    void load_missingFile_thenGetVerifierUrls_throws() {
        TenantCustomDomainsLoader loader = new TenantCustomDomainsLoader(
                new DefaultResourceLoader(), "file:/nonexistent/tenants-custom-domains.yaml");
        loader.load();
        assertThrows(IllegalStateException.class, () -> loader.getVerifierUrls("kpmg"));
    }

    // ── findVerifierUrls ────────────────────────────────────────────────────

    @Test
    void findVerifierUrls_knownTenant_returnsPopulatedOptional() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifiers:
                      - https://kpmg.eudistack.net/verifier
                    wallet: https://kpmg.wallet.eudistack.net
                """);

        assertTrue(loader.findVerifierUrls("kpmg").isPresent());
        assertEquals(List.of("https://kpmg.eudistack.net/verifier"),
                loader.findVerifierUrls("kpmg").get());
    }

    @Test
    void findVerifierUrls_unknownTenant_returnsEmpty() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifiers:
                      - https://kpmg.eudistack.net/verifier
                    wallet: https://kpmg.wallet.eudistack.net
                """);

        assertTrue(loader.findVerifierUrls("unknown").isEmpty());
    }

    // ── legacy wallet field (EUD-305) ───────────────────────────────────────

    /**
     * The issuer no longer resolves wallets, but registries still carry {@code wallet} where other
     * consumers read it (the local nginx entrypoint), so the field must not stop the startup.
     */
    @Test
    void load_legacyWalletField_isIgnored() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("""
                tenants:
                  - id: dome
                    issuer: https://issuer.dome-marketplace.org
                    verifiers:
                      - https://verifier.dome-marketplace.org
                    wallet: https://wallet.dome-marketplace.org/wallet
                """);

        assertEquals(List.of("https://verifier.dome-marketplace.org"), loader.getVerifierUrls("dome"));
    }

    @Test
    void load_withoutWalletField_loads() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("""
                tenants:
                  - id: dome
                    issuer: https://issuer.dome-marketplace.org
                    verifiers:
                      - https://verifier.dome-marketplace.org
                """);

        assertEquals(List.of("https://verifier.dome-marketplace.org"), loader.getVerifierUrls("dome"));
    }

    // ── unknown tenant ──────────────────────────────────────────────────────

    @Test
    void getVerifierUrls_unknownTenant_throws() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifiers:
                      - https://kpmg.eudistack.net/verifier
                    wallet: https://kpmg.wallet.eudistack.net
                """);
        assertThrows(IllegalStateException.class, () -> loader.getVerifierUrls("unknown"));
    }

    // ── validation failures (fail at startup) ───────────────────────────────

    @Test
    void load_blankTenantId_throwsAtStartup() {
        assertThrows(IllegalStateException.class, () -> loaderFrom("""
                tenants:
                  - id: ""
                    issuer: https://kpmg.eudistack.net
                    verifiers:
                      - https://kpmg.eudistack.net/verifier
                    wallet: https://kpmg.wallet.eudistack.net
                """));
    }

    @Test
    void load_emptyVerifiersList_throwsAtStartup() {
        assertThrows(IllegalStateException.class, () -> loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifiers: []
                    wallet: https://kpmg.wallet.eudistack.net
                """));
    }

    @Test
    void load_missingVerifiersField_throwsAtStartup() {
        assertThrows(IllegalStateException.class, () -> loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    wallet: https://kpmg.wallet.eudistack.net
                """));
    }

    @Test
    void load_blankVerifierUrl_throwsAtStartup() {
        assertThrows(IllegalStateException.class, () -> loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifiers:
                      - ""
                    wallet: https://kpmg.wallet.eudistack.net
                """));
    }

    @Test
    void load_invalidVerifierUrl_throwsAtStartup() {
        assertThrows(IllegalStateException.class, () -> loaderFrom("""
                tenants:
                  - id: kpmg
                    issuer: https://kpmg.eudistack.net
                    verifiers:
                      - "not a valid uri with spaces here"
                    wallet: https://kpmg.wallet.eudistack.net
                """));
    }

    // ── environmentLabel ────────────────────────────────────────────────────

    private static final String LABELLED_YAML = """
            tenants:
              - id: dome-dev
                issuer: https://issuer.dev.dome.example
                verifiers:
                  - https://verifier.dev.dome.example
                wallet: https://wallet.dev.dome.example
                environmentLabel: Dev
              - id: dome
                issuer: https://issuer.dome.example
                verifiers:
                  - https://verifier.dome.example
                wallet: https://wallet.dome.example
            """;

    @Test
    void findEnvironmentLabelByIssuerHost_entryWithLabel_returnsLabel() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom(LABELLED_YAML);

        assertEquals(java.util.Optional.of("Dev"), loader.findEnvironmentLabelByIssuerHost("issuer.dev.dome.example"));
    }

    @Test
    void findEnvironmentLabelByIssuerHost_entryWithoutLabel_returnsEmpty() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom(LABELLED_YAML);

        assertTrue(loader.findEnvironmentLabelByIssuerHost("issuer.dome.example").isEmpty());
    }

    @Test
    void findEnvironmentLabelByIssuerHost_unknownOrBlankHost_returnsEmpty() throws IOException {
        TenantCustomDomainsLoader loader = loaderFrom(LABELLED_YAML);

        assertTrue(loader.findEnvironmentLabelByIssuerHost("other.example").isEmpty());
        assertTrue(loader.findEnvironmentLabelByIssuerHost(" ").isEmpty());
        assertTrue(loader.findEnvironmentLabelByIssuerHost(null).isEmpty());
    }
}
