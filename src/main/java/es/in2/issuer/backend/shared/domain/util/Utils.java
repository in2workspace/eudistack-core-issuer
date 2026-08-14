package es.in2.issuer.backend.shared.domain.util;

import com.nimbusds.jose.util.Base64URL;
import reactor.core.publisher.Mono;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.UUID;

public final class Utils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private Utils() {
        throw new IllegalStateException("Utility class");
    }

    public static Mono<String> generateCustomNonce() {
        return convertUUIDToBytes(UUID.randomUUID())
                .map(uuidBytes -> Base64URL.encode(uuidBytes).toString());
    }

    // Dedicated generator for values requiring high entropy guarantees, e.g. OAuth
    // authorization codes (RFC 6749 §10.10 / RFC 6819 §5.1.4.2-2). Unlike
    // generateCustomNonce(), which derives from a UUIDv4 (6 of its 128 bits are
    // fixed version/variant bits, not random), this draws directly from a CSPRNG
    // so every bit counts toward the measured entropy.
    public static Mono<String> generateSecureAuthorizationCode() {
        return Mono.fromSupplier(() -> {
            byte[] randomBytes = new byte[32];
            SECURE_RANDOM.nextBytes(randomBytes);
            return Base64URL.encode(randomBytes).toString();
        });
    }

    private static Mono<byte[]> convertUUIDToBytes(UUID uuid) {
        return Mono.fromSupplier(() -> {
            ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
            byteBuffer.putLong(uuid.getMostSignificantBits());
            byteBuffer.putLong(uuid.getLeastSignificantBits());
            return byteBuffer.array();
        });
    }
}
