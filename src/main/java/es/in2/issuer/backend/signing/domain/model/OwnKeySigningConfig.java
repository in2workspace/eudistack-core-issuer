package es.in2.issuer.backend.signing.domain.model;

import java.util.List;

/**
 * Own-key signing configuration of a tenant: a reference to the KMS key plus the public
 * certificate material. Never holds secrets.
 *
 * <p>{@code keyTenantTag} is not stored in the database: it is the {@code Tenant} tag read from the
 * KMS key when the configuration is loaded, and it travels with the configuration in the cache so
 * that it is not read on every signature. Being part of the record, it takes part in equality: a
 * configuration reloaded with another tag (the key was re-tagged) is not the one a request already
 * used, which the signing configuration scope handles as any other configuration change (EUD-289 M4).
 *
 * @param kmsKeyRef         KMS key identifier (ARN)
 * @param algorithm         JWS algorithm of the key; only {@value #ES256} is supported
 * @param certificateChain  base64 DER certificates, leaf first, root excluded (the JWS {@code x5c} value)
 * @param keyTenantTag      value of the {@code Tenant} tag of the KMS key; {@code null} when the key has no
 *                          such tag or the tag has not been read (signing then refuses to use the key)
 */
public record OwnKeySigningConfig(
        String kmsKeyRef,
        String algorithm,
        List<String> certificateChain,
        String keyTenantTag
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
        if (keyTenantTag != null && keyTenantTag.isBlank()) {
            keyTenantTag = null;
        }
    }

    /** A configuration whose key tag has not been read yet. */
    public OwnKeySigningConfig(String kmsKeyRef, String algorithm, List<String> certificateChain) {
        this(kmsKeyRef, algorithm, certificateChain, null);
    }

    public OwnKeySigningConfig withKeyTenantTag(String tag) {
        return new OwnKeySigningConfig(kmsKeyRef, algorithm, certificateChain, tag);
    }
}
