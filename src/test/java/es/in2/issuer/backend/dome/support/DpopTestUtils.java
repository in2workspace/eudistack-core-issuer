package es.in2.issuer.backend.dome.support;

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

public class DpopTestUtils {

    private DpopTestUtils() {}

    /**
     * Generates a dynamic, valid DPoP proof for tests.
     */
    public static String generateValidDpop(String htm, String htu) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\"}".getBytes()
        );

        String payloadJson = "{\"jti\":\"" + UUID.randomUUID() +
                "\",\"htm\":\"" + htm +
                "\",\"htu\":\"" + htu +
                "\",\"iat\":" + Instant.now().getEpochSecond() + "}";

        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes());

        return header + "." + payload + ".valid-signature";
    }
}