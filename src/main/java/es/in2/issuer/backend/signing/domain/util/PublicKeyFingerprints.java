package es.in2.issuer.backend.signing.domain.util;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

/**
 * SHA-256 fingerprints of a public key's SubjectPublicKeyInfo (SPKI) DER encoding.
 *
 * The fingerprint is the value {@code openssl pkey -pubin -outform DER | openssl dgst -sha256}
 * prints, so an operator can compare it against a key held outside the issuer (for example the
 * public key a KMS returns from {@code GetPublicKey}) without sharing the key itself.
 */
public final class PublicKeyFingerprints {

    private static final String[] SUPPORTED_KEY_ALGORITHMS = {"EC", "RSA"};

    private PublicKeyFingerprints() {}

    /**
     * @param certificate the certificate whose public key is fingerprinted
     * @return lowercase hex SHA-256 of the certificate's SPKI DER
     * @throws IllegalArgumentException if the certificate is null
     */
    public static String spkiSha256(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate is required to compute an SPKI fingerprint");
        }
        return sha256Hex(certificate.getPublicKey().getEncoded());
    }

    /**
     * The key is parsed and re-encoded before hashing, so two DER encodings of the same key
     * fingerprint identically.
     *
     * @param spkiDer SubjectPublicKeyInfo DER of an EC or RSA key
     * @return lowercase hex SHA-256 of the canonical SPKI DER
     * @throws IllegalArgumentException if the input is null, empty or not an EC/RSA SPKI
     */
    public static String spkiSha256(byte[] spkiDer) {
        if (spkiDer == null || spkiDer.length == 0) {
            throw new IllegalArgumentException("SPKI DER is null or empty");
        }
        return sha256Hex(parse(spkiDer).getEncoded());
    }

    private static PublicKey parse(byte[] spkiDer) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(spkiDer);
        for (String algorithm : SUPPORTED_KEY_ALGORITHMS) {
            try {
                return KeyFactory.getInstance(algorithm).generatePublic(spec);
            } catch (GeneralSecurityException e) {
                // not this key algorithm; the next one is tried, and if none fits we fail below
            }
        }
        throw new IllegalArgumentException("SPKI DER is not a valid EC or RSA SubjectPublicKeyInfo");
    }

    private static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
