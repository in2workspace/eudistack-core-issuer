package es.in2.issuer.backend.signing.domain.onboarding;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * A certificate chain that passed {@link OwnKeyCertificateValidator}: what the onboarding needs from it
 * afterwards. The chain is leaf first and root excluded, as stored and as published in the JWS {@code x5c}.
 */
public record ValidatedOwnKeyCertificate(List<X509Certificate> chain) {

    public ValidatedOwnKeyCertificate {
        chain = List.copyOf(chain);
    }

    public X509Certificate leaf() {
        return chain.getFirst();
    }

    /** The chain as the base64 DER strings of the JWS {@code x5c} header. */
    public List<String> chainBase64() {
        return chain.stream().map(ValidatedOwnKeyCertificate::base64Der).toList();
    }

    /** DER SubjectPublicKeyInfo of the leaf: what KMS {@code GetPublicKey} must return. */
    public byte[] spkiDer() {
        return leaf().getPublicKey().getEncoded();
    }

    /** SHA-256 of {@link #spkiDer()}: the key of {@code public.signing_spki_reservation}. */
    public byte[] spkiSha256() {
        return sha256(spkiDer());
    }

    public String spkiSha256Hex() {
        return HexFormat.of().formatHex(spkiSha256());
    }

    /** SHA-256 of the DER leaf certificate, lowercase hexadecimal: the fingerprint the audit event carries. */
    public String certificateSha256Hex() {
        try {
            return HexFormat.of().formatHex(sha256(leaf().getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("The validated certificate cannot be encoded", e);
        }
    }

    private static String base64Der(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("The validated certificate cannot be encoded", e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("The JDK does not provide SHA-256", e);
        }
    }
}
