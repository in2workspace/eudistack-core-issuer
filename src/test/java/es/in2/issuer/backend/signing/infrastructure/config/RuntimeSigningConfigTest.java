package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.infrastructure.properties.RemoteSignatureProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.SigningRuntimeConfigProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class RuntimeSigningConfigTest {

    private RuntimeSigningConfig createConfig(String defaultProvider) {
        var runtimeProps = new SigningRuntimeConfigProperties(true, true, defaultProvider);
        var remoteProps = new RemoteSignatureProperties(
                "https://mock-qtsp.example.com",
                "client", "secret", "cred-001", "password", "PT10M",
                "sign-hash"
        );
        return new RuntimeSigningConfig(runtimeProps, remoteProps);
    }

    private RuntimeSigningConfig createConfigWithoutRemote(String defaultProvider) {
        var runtimeProps = new SigningRuntimeConfigProperties(true, true, defaultProvider);
        var remoteProps = new RemoteSignatureProperties(null, null, null, null, null, null, null);
        return new RuntimeSigningConfig(runtimeProps, remoteProps);
    }

    @Test
    void defaultProvider_shouldBeConfiguredValue() {
        RuntimeSigningConfig config = createConfig("altia-mock-qtsp");
        assertEquals("altia-mock-qtsp", config.getProvider());
    }

    @Test
    void defaultProvider_shouldLoadRemoteSignatureFromProperties() {
        RuntimeSigningConfig config = createConfig("altia-mock-qtsp");
        assertNotNull(config.getRemoteSignature());
        assertEquals("https://mock-qtsp.example.com", config.getRemoteSignature().url());
        assertEquals("client", config.getRemoteSignature().clientId());
        assertEquals("PT10M", config.getRemoteSignature().certificateInfoCacheTtl());
    }

    @Test
    void defaultProvider_withoutRemoteConfig_shouldHaveNullRemoteSignature() {
        RuntimeSigningConfig config = createConfigWithoutRemote("altia-mock-qtsp");
        assertEquals("altia-mock-qtsp", config.getProvider());
        assertNull(config.getRemoteSignature());
    }

    @Test
    void setProvider_shouldUpdateValue() {
        RuntimeSigningConfig config = createConfig("altia-mock-qtsp");
        config.setProvider("digitel-ts");
        assertEquals("digitel-ts", config.getProvider());
    }

    @Test
    void setProvider_shouldOverridePreviousValue() {
        RuntimeSigningConfig config = createConfig("altia-mock-qtsp");
        config.setProvider("digitel-ts");
        config.setProvider("another-qtsp");
        assertEquals("another-qtsp", config.getProvider());
    }

    @Test
    void provider_shouldBeThreadSafe() throws InterruptedException {
        RuntimeSigningConfig config = createConfig("altia-mock-qtsp");
        int threads = 10;
        var executor = Executors.newFixedThreadPool(threads);
        CountDownLatch latch = new CountDownLatch(threads);

        for (int i = 0; i < threads; i++) {
            final int index = i;
            executor.submit(() -> {
                config.setProvider("provider-" + index);
                latch.countDown();
            });
        }

        latch.await(2, TimeUnit.SECONDS);
        executor.shutdown();
        assertNotNull(config.getProvider());
        assertTrue(config.getProvider().startsWith("provider-"));
    }
}
