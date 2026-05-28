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

    public static final String HOLDER_1_THUMBPRINT = "N-5a-s1M9T8y3t1jP_Z2vQ-X5lY8K7G6V_x_Q_abc123=";
    public static final String HOLDER_2_THUMBPRINT = "A-1b-c2D3E4f5g6H_I7jK-L8mN9O0P_q_R_xyz987=";

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
        return UUID.randomUUID().toString();
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