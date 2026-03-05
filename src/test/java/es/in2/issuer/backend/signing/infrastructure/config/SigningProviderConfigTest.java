package es.in2.issuer.backend.signing.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.service.SigningRecoveryService;
import es.in2.issuer.backend.signing.domain.service.JadesHeaderBuilderService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.domain.service.RemoteSignatureService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignDocSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.CscSignHashSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.InMemorySigningProvider;
import es.in2.issuer.backend.signing.infrastructure.properties.CscSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class SigningProviderConfigTest {

    @TempDir
    static Path tempDir;

    private static String certPath;
    private static String keyPath;

    @Mock private RuntimeSigningConfig runtimeSigningConfig;

    @Mock private RemoteSignatureService remoteSignatureService;
    @Mock private SigningRecoveryService signingRecoveryService;

    @Mock private QtspAuthClient qtspAuthClient;
    @Mock private QtspIssuerService qtspIssuerService;
    @Mock private JwsSignHashService jwsSignHashService;
    @Mock private JadesHeaderBuilderService jadesHeaderBuilder;
    @Mock private CscSigningProperties cscSigningProperties;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeAll
    static void generateTestCertAndKey() throws Exception {
        // Generate an EC key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();

        // Use keytool-like approach: generate self-signed cert via ProcessBuilder
        Path keyFile = tempDir.resolve("test-key.pem");
        String keyPem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded()) +
                "\n-----END PRIVATE KEY-----\n";
        Files.writeString(keyFile, keyPem);
        keyPath = keyFile.toString();

        // Generate self-signed certificate using openssl
        Path certFile = tempDir.resolve("test-cert.pem");
        ProcessBuilder pb = new ProcessBuilder(
                "openssl", "req", "-new", "-x509",
                "-key", keyPath,
                "-out", certFile.toString(),
                "-days", "365",
                "-subj", "/CN=Test",
                "-sha256"
        );
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        int exitCode = proc.waitFor();
        if (exitCode != 0) {
            throw new IllegalStateException("openssl failed with exit code " + exitCode +
                    ": " + new String(proc.getInputStream().readAllBytes()));
        }
        certPath = certFile.toString();
    }

    @Test
    void signingProvider_createsDelegatingProviderWithExpectedKeysAndTypes() {
        SigningProviderConfig config = new SigningProviderConfig();

        SigningProvider provider = config.signingProvider(
                runtimeSigningConfig,
                remoteSignatureService,
                signingRecoveryService,
                qtspAuthClient,
                qtspIssuerService,
                jwsSignHashService,
                jadesHeaderBuilder,
                cscSigningProperties,
                objectMapper,
                certPath,
                keyPath
        );

        assertNotNull(provider);
        assertTrue(provider instanceof DelegatingSigningProvider);

        Map<String, SigningProvider> providersByKey =
                (Map<String, SigningProvider>) ReflectionTestUtils.getField(provider, "providersByKey");

        assertNotNull(providersByKey);
        assertEquals(3, providersByKey.size());
        assertTrue(providersByKey.containsKey("in-memory"));
        assertTrue(providersByKey.containsKey("csc-sign-doc"));
        assertTrue(providersByKey.containsKey("csc-sign-hash"));

        assertTrue(providersByKey.get("in-memory") instanceof InMemorySigningProvider);
        assertTrue(providersByKey.get("csc-sign-doc") instanceof CscSignDocSigningProvider);
        assertTrue(providersByKey.get("csc-sign-hash") instanceof CscSignHashSigningProvider);
    }

    @Test
    void signingProvider_wiresDependenciesIntoCscProviders() {
        SigningProviderConfig config = new SigningProviderConfig();

        SigningProvider provider = config.signingProvider(
                runtimeSigningConfig,
                remoteSignatureService,
                signingRecoveryService,
                qtspAuthClient,
                qtspIssuerService,
                jwsSignHashService,
                jadesHeaderBuilder,
                cscSigningProperties,
                objectMapper,
                certPath,
                keyPath
        );

        Map<String, SigningProvider> providersByKey =
                (Map<String, SigningProvider>) ReflectionTestUtils.getField(provider, "providersByKey");

        // csc-sign-doc wiring
        Object cscDoc = providersByKey.get("csc-sign-doc");
        assertSame(remoteSignatureService, ReflectionTestUtils.getField(cscDoc, "remoteSignatureService"));
        assertSame(signingRecoveryService, ReflectionTestUtils.getField(cscDoc, "signingRecoveryService"));

        // csc-sign-hash wiring
        Object cscHash = providersByKey.get("csc-sign-hash");
        assertSame(qtspAuthClient, ReflectionTestUtils.getField(cscHash, "qtspAuthClient"));
        assertSame(qtspIssuerService, ReflectionTestUtils.getField(cscHash, "qtspIssuerService"));
        assertSame(jwsSignHashService, ReflectionTestUtils.getField(cscHash, "jwsSignHashService"));
        assertSame(jadesHeaderBuilder, ReflectionTestUtils.getField(cscHash, "jadesHeaderBuilder"));
        assertSame(cscSigningProperties, ReflectionTestUtils.getField(cscHash, "cscSigningProperties"));
        assertSame(objectMapper, ReflectionTestUtils.getField(cscHash, "objectMapper"));
    }

    @Test
    void signingProvider_setsRuntimeSigningConfigIntoDelegatingProvider() {
        SigningProviderConfig config = new SigningProviderConfig();

        SigningProvider provider = config.signingProvider(
                runtimeSigningConfig,
                remoteSignatureService,
                signingRecoveryService,
                qtspAuthClient,
                qtspIssuerService,
                jwsSignHashService,
                jadesHeaderBuilder,
                cscSigningProperties,
                objectMapper,
                certPath,
                keyPath
        );

        assertSame(runtimeSigningConfig, ReflectionTestUtils.getField(provider, "runtimeSigningConfig"));
    }
}
