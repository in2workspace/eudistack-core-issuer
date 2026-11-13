package es.in2.issuer.backend.shared.domain.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;

/**
 * Turns a recipient identifier (email, holder id) into a tenant-scoped pseudonym for audit correlation, per AD-2
 * (EUD-170 / US-04): the raw value is never stored, logged or returned.
 *
 * <p>The pseudonym is an HMAC-SHA256 with the tenant's secret key (EUD-267, TD-20 of EUD-254; AD-3 of its design),
 * the one kept outside the database for the search identifier fingerprints. A key of its own is derived from it, so
 * a pseudonym never equals the fingerprint of the same value. Without the key, a pseudonym cannot be reversed by
 * trying likely emails, which the tenant id it used before as the key allowed.
 */
public final class RecipientPseudonymizer {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final byte[] PURPOSE = "eudistack-recipient-pseudonym".getBytes(StandardCharsets.UTF_8);
    private static final int MIN_KEY_BYTES = 32;

    /**
     * @param tenantSecretKey the tenant's secret key, at least 32 bytes
     *                        ({@link es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort})
     * @param raw             the value to pseudonymize, not blank
     */
    public String hash(byte[] tenantSecretKey, String raw) {
        if (tenantSecretKey == null || tenantSecretKey.length < MIN_KEY_BYTES) {
            throw new IllegalArgumentException("RecipientPseudonymizer requires the tenant secret key ("
                    + MIN_KEY_BYTES + " bytes or more)");
        }
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("RecipientPseudonymizer requires a non-blank value to pseudonymize");
        }
        byte[] purposeKey = hmac(tenantSecretKey, PURPOSE);
        return HexFormat.of().formatHex(hmac(purposeKey, raw.getBytes(StandardCharsets.UTF_8)));
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to compute recipient pseudonym", e);
        }
    }
}
