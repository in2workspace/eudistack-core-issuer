package es.in2.issuer.backend.dome;

import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Factory class providing synthetic test vectors and fixtures
 * for DOME Synchronization tests (EUDISTACK-144).
 */
public class DomeSyncFixtureFactory {

    public static final String HOLDER_1_THUMBPRINT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public static final String HOLDER_2_THUMBPRINT = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";

    /**
     * Loads the successful credentials JSON for Holder 1.
     */
    public static String getHolder1CredentialsResponse() {
        return loadFixture("holder-1-credentials.json");
    }

    /**
     * Loads the empty credentials JSON for Holder 2.
     */
    public static String getHolder2EmptyResponse() {
        return loadFixture("holder-2-empty.json");
    }

    /**
     * Generates a simulated idempotency key (UUID v7 format simulation)
     */
    public static String generateIdempotencyKey() {
        return "018f2a99-9b80-7fc4-a82f-2c8e3100b468";
    }

    /**
     * Helper method to read files from the resources/fixtures/dome folder.
     */
    private static String loadFixture(String fileName) {
        String path = "/fixtures/dome/" + fileName;
        try (InputStream is = DomeSyncFixtureFactory.class.getResourceAsStream(path)) {
            if (is == null) {
                throw new IllegalArgumentException("Fixture no encontrado: " + path);
            }
            return StreamUtils.copyToString(is, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Error leyendo el fixture: " + fileName, e);
        }
    }
}