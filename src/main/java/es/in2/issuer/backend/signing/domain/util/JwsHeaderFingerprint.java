package es.in2.issuer.backend.signing.domain.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents.SignatureProof;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Reads, from the header of a signed JWS, the algorithm and the fingerprint of the signing certificate,
 * which are what the audit trail keeps of a signature. Nothing else of the certificate is read.
 */
public final class JwsHeaderFingerprint {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String FINGERPRINT_PREFIX = "sha256:";

    private JwsHeaderFingerprint() {
    }

    /** Empty when the value is not a compact JWS or its header lacks the algorithm or the certificate. */
    public static Optional<SignatureProof> of(String compactJws) {
        if (compactJws == null || compactJws.isBlank()) {
            return Optional.empty();
        }
        String jws = compactJws.split("~", 2)[0];
        String[] segments = jws.split("\\.");
        if (segments.length < 2) {
            return Optional.empty();
        }
        try {
            JsonNode header = OBJECT_MAPPER.readTree(Base64.getUrlDecoder().decode(segments[0]));
            JsonNode algorithm = header.get("alg");
            JsonNode certificateChain = header.get("x5c");
            if (algorithm == null || !algorithm.isTextual()
                    || certificateChain == null || !certificateChain.isArray() || certificateChain.isEmpty()) {
                return Optional.empty();
            }
            byte[] certificate = Base64.getDecoder().decode(certificateChain.get(0).asText().getBytes(StandardCharsets.UTF_8));
            return Optional.of(new SignatureProof(algorithm.asText(), fingerprintOf(certificate)));
        } catch (IOException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** {@code sha256:<hex>} of the value, the form the audit trail keeps for anything it must not copy. */
    public static String fingerprintOf(byte[] value) {
        return FINGERPRINT_PREFIX + sha256(value);
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is mandated by every Java platform", e);
        }
    }
}
