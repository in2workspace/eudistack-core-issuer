package es.in2.issuer.backend.shared.domain.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** SHA-256 digests in lower-case hex, for keys that must not keep their input in clear. */
public final class Sha256 {

    private Sha256() {
    }

    public static String hex(String value) {
        return hex(value.getBytes(StandardCharsets.UTF_8));
    }

    public static String hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
