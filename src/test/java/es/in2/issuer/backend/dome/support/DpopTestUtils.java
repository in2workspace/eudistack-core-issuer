package es.in2.issuer.backend.dome.support;

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Utility class to generate synthetic DPoP tokens for integration tests.
 */
public class DpopTestUtils {

    private DpopTestUtils() {}

    /**
     * Standard method for happy paths: Generates a random JTI automatically.
     */
    public static String generateValidDpop(String htm, String htu) {
        return generateDpopWithJti(htm, htu, UUID.randomUUID().toString());
    }

    /**
     * Advanced method for testing replay attacks: Allows passing a specific JTI.
     */
    public static String generateDpopWithJti(String htm, String htu, String jti) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\"}".getBytes()
        );

        String payloadJson = "{\"jti\":\"" + jti +
                "\",\"htm\":\"" + htm +
                "\",\"htu\":\"" + htu +
                "\",\"iat\":" + Instant.now().getEpochSecond() + "}";

        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes());

        return header + "." + payload + ".valid-signature";
    }
}