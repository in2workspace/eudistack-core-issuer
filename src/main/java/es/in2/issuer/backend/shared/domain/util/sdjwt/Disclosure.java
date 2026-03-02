package es.in2.issuer.backend.shared.domain.util.sdjwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/**
 * SD-JWT Disclosure per SD-JWT VC specification (SD-JWT VC draft-14).
 * A disclosure is a base64url-encoded JSON array: [salt, claim_name, claim_value].
 */
public record Disclosure(
        String salt,
        String claimName,
        Object claimValue,
        String encoded
) {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Create a new disclosure for a claim. */
    public static Disclosure create(String claimName, Object claimValue) {
        byte[] saltBytes = new byte[16];
        RANDOM.nextBytes(saltBytes);
        String salt = Base64.getUrlEncoder().withoutPadding().encodeToString(saltBytes);

        try {
            String json = MAPPER.writeValueAsString(List.of(salt, claimName, claimValue));
            String encoded = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(json.getBytes(StandardCharsets.UTF_8));
            return new Disclosure(salt, claimName, claimValue, encoded);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to create disclosure for claim: " + claimName, e);
        }
    }

    /** Compute the SHA-256 digest of this disclosure (for _sd array in JWT). */
    public String digest() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(encoded.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute disclosure digest", e);
        }
    }

    /** Parse a disclosure from its base64url-encoded form. */
    public static Disclosure parse(String encoded) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encoded);
            List<?> array = MAPPER.readValue(decoded, List.class);
            if (array.size() != 3) {
                throw new IllegalArgumentException("Disclosure must be a 3-element array");
            }
            return new Disclosure(
                    (String) array.get(0),
                    (String) array.get(1),
                    array.get(2),
                    encoded
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse disclosure: " + e.getMessage(), e);
        }
    }
}
