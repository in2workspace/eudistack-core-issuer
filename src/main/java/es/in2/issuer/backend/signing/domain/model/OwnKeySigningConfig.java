package es.in2.issuer.backend.signing.domain.model;

import java.util.List;

/**
 * Own-key signing configuration of a tenant: a reference to the KMS key plus the public
 * certificate material. Never holds secrets.
 *
 * @param kmsKeyRef         KMS key identifier (ARN)
 * @param algorithm         JWS algorithm of the key; only {@value #ES256} is supported
 * @param certificateChain  base64 DER certificates, leaf first, root excluded (the JWS {@code x5c} value)
 */
public record OwnKeySigningConfig(
        String kmsKeyRef,
        String algorithm,
        List<String> certificateChain
) {
    public static final String ES256 = "ES256";

    public OwnKeySigningConfig {
        if (kmsKeyRef == null || kmsKeyRef.isBlank()) {
            throw new IllegalArgumentException("own-key configuration has no KMS key reference");
        }
        if (!ES256.equals(algorithm)) {
            throw new IllegalArgumentException("own-key configuration has an unsupported algorithm");
        }
        if (certificateChain == null || certificateChain.isEmpty()
                || certificateChain.stream().anyMatch(c -> c == null || c.isBlank())) {
            throw new IllegalArgumentException("own-key configuration has no valid certificate chain");
        }
        certificateChain = List.copyOf(certificateChain);
    }
}
