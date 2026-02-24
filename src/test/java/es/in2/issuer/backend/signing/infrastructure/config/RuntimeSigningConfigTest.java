package es.in2.issuer.backend.signing.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class RuntimeSigningConfigTest {

    @Test
    void defaultProvider_shouldBeInMemory() {
        RuntimeSigningConfig config = new RuntimeSigningConfig();

        assertEquals("in-memory", config.getProvider());
    }

    @Test
    void setProvider_shouldUpdateValue() {
        RuntimeSigningConfig config = new RuntimeSigningConfig();

        config.setProvider("csc-sign-hash");

        assertEquals("csc-sign-hash", config.getProvider());
    }

    @Test
    void setProvider_shouldOverridePreviousValue() {
        RuntimeSigningConfig config = new RuntimeSigningConfig();

        config.setProvider("csc-sign-doc");
        config.setProvider("csc-sign-hash");

        assertEquals("csc-sign-hash", config.getProvider());
    }

    @Test
    void provider_shouldBeThreadSafe() throws InterruptedException {
        RuntimeSigningConfig config = new RuntimeSigningConfig();

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