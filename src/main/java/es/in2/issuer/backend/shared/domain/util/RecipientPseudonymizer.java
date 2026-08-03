package es.in2.issuer.backend.shared.domain.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Turns a recipient identifier (email, holder id) into a tenant-scoped pseudonym for audit
 * correlation, per AD-2 (EUD-170 / US-04): the raw value is never stored, logged or returned.
 *
 * <p>The tenant id is used as the HMAC key, so the same recipient identifier pseudonymizes to a
 * different, non-correlatable value in a different tenant (NFR-S-02).
 */
public final class RecipientPseudonymizer {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public String hash(String tenantId, String raw) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("RecipientPseudonymizer requires a tenantId to scope the hash");
        }
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("RecipientPseudonymizer requires a non-blank value to pseudonymize");
        }

        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(tenantId.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            byte[] digest = mac.doFinal(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Unable to compute recipient pseudonym", e);
        }
    }
}
