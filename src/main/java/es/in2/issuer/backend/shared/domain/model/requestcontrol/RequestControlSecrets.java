package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

/**
 * The secret of the idempotency and the volume counters (EUD-269), its own and not reused from any other key
 * (SEC-15): {@code ISSUER_IDEMPOTENCY_SECRET}, the same on every instance, kept in the secrets manager.
 *
 * <p>Every key used with it is derived with HKDF-SHA256 (RFC 5869, SEC-14), one per purpose, so no two uses
 * share a key. Each secret has an id of one byte, written as the format byte of the kept responses, so the
 * secret can be rotated: while the previous one is configured too (the 24 hours of the retention), the keys
 * kept with it are still found and their responses opened.
 *
 * @param current  the secret every new key is kept with
 * @param previous the secret before the last rotation, or {@code null}
 */
public record RequestControlSecrets(Secret current, Secret previous) {

    /** The shortest secret accepted: 32 bytes, the length of the HMAC-SHA256 keys derived from it. */
    public static final int MIN_SECRET_BYTES = 32;

    /** Purposes of the derived keys: changing one changes every stored digest of that purpose. */
    public static final String IDEMPOTENCY_SCOPE_KEY = "idempotency-scope-key";
    public static final String IDEMPOTENCY_REQUEST_HASH = "idempotency-request-hash";
    public static final String IDEMPOTENCY_RESPONSE_KEY = "idempotency-response-key";
    public static final String VOLUME_COUNTER_KEY = "volume-counter-key";

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final byte[] HKDF_SALT = "eudistack-issuer-request-control".getBytes(StandardCharsets.UTF_8);

    public RequestControlSecrets {
        Objects.requireNonNull(current, "current");
        if (previous != null && previous.id() == current.id()) {
            throw new IllegalArgumentException("The current and the previous idempotency secrets need different ids");
        }
    }

    public RequestControlSecrets(Secret current) {
        this(current, null);
    }

    /** The secrets a kept key may have been stored with: the current one first. */
    public Optional<Secret> previousSecret() {
        return Optional.ofNullable(previous);
    }

    /** The secret with this id, among the current and the previous one. */
    public Optional<Secret> byId(int id) {
        if (current.id() == id) {
            return Optional.of(current);
        }
        return previous != null && previous.id() == id ? Optional.of(previous) : Optional.empty();
    }

    /**
     * One secret of the request control.
     *
     * @param id    1 to 255, written as the format byte of the responses kept with it
     * @param value the secret, at least {@value #MIN_SECRET_BYTES} bytes
     */
    public record Secret(int id, byte[] value) {

        public Secret {
            if (id < 1 || id > 255) {
                throw new IllegalArgumentException("The id of an idempotency secret must be between 1 and 255");
            }
            Objects.requireNonNull(value, "value");
            if (value.length < MIN_SECRET_BYTES) {
                throw new IllegalArgumentException("An idempotency secret needs at least " + MIN_SECRET_BYTES + " bytes");
            }
            value = value.clone();
        }

        public static Secret of(int id, String value) {
            Objects.requireNonNull(value, "value");
            return new Secret(id, value.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public byte[] value() {
            return value.clone();
        }

        /** HKDF-SHA256 of this secret for one purpose: a 32-byte key. */
        public byte[] derive(String purpose) {
            byte[] pseudoRandomKey = hmac(HKDF_SALT, value);
            // One block of the expansion is enough for 32 bytes: T(1) = HMAC(PRK, info || 0x01).
            ByteArrayOutputStream info = new ByteArrayOutputStream();
            info.writeBytes(purpose.getBytes(StandardCharsets.UTF_8));
            info.write(1);
            return hmac(pseudoRandomKey, info.toByteArray());
        }

        /** HMAC-SHA256 of the input with the key of one purpose. */
        public byte[] macBytes(String purpose, byte[] input) {
            return hmac(derive(purpose), input);
        }

        /** {@link #macBytes} in lower-case hex. */
        public String mac(String purpose, byte[] input) {
            return HexFormat.of().formatHex(macBytes(purpose, input));
        }

        public String mac(String purpose, String input) {
            return mac(purpose, input.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Secret(int thatId, byte[] thatValue) && id == thatId && Arrays.equals(value, thatValue);
        }

        @Override
        public int hashCode() {
            return 31 * id + Arrays.hashCode(value);
        }

        /** The secret is never printed. */
        @Override
        public String toString() {
            return "Secret[id=" + id + ", value=redacted]";
        }
    }

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }
}
