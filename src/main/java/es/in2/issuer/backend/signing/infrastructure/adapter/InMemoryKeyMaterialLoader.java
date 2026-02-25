package es.in2.issuer.backend.signing.infrastructure.adapter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

public final class InMemoryKeyMaterialLoader {

    private InMemoryKeyMaterialLoader() {}

    public record KeyMaterial(
            ECPrivateKey privateKey,
            List<X509Certificate> certificateChain
    ) {}

    /** Load from filesystem paths (recommended for k8s mounted secrets). */
    public static KeyMaterial loadFromPaths(String privateKeyPath, String certChainPath) {
        Objects.requireNonNull(privateKeyPath, "privateKeyPath is required");
        Objects.requireNonNull(certChainPath, "certChainPath is required");

        try {
            String keyPem = Files.readString(Path.of(privateKeyPath), StandardCharsets.UTF_8);
            String certPem = Files.readString(Path.of(certChainPath), StandardCharsets.UTF_8);
            return loadFromPemStrings(keyPem, certPem);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read key material from paths", e);
        }
    }

    /** Load from PEM strings (useful if you inject via env vars). */
    public static KeyMaterial loadFromPemStrings(String privateKeyPem, String certChainPem) {
        if (privateKeyPem == null || privateKeyPem.isBlank()) {
            throw new IllegalArgumentException("privateKeyPem is required");
        }
        if (certChainPem == null || certChainPem.isBlank()) {
            throw new IllegalArgumentException("certChainPem is required");
        }

        ECPrivateKey privateKey = parseEcPrivateKeyPkcs8(privateKeyPem);
        List<X509Certificate> chain = parseX509Chain(certChainPem);

        if (chain.isEmpty()) {
            throw new IllegalArgumentException("certChainPem did not contain any X.509 certificates");
        }

        // Basic sanity checks
        if (!(chain.getFirst().getPublicKey() instanceof java.security.interfaces.ECPublicKey)) {
            throw new IllegalArgumentException("Leaf certificate does not contain an EC public key");
        }

        return new KeyMaterial(privateKey, chain);
    }

    /** Parses PKCS#8 EC private key from PEM: -----BEGIN PRIVATE KEY----- */
    private static ECPrivateKey parseEcPrivateKeyPkcs8(String pem) {
        try {
            String normalized = pem
                    .replace("\r", "")
                    .trim();

            String base64 = extractPemBlock(normalized, "PRIVATE KEY");
            byte[] der = Base64.getDecoder().decode(base64);

            KeyFactory kf = KeyFactory.getInstance("EC");
            return (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid EC private key PEM (expected PKCS#8 BEGIN PRIVATE KEY)", e);
        }
    }

    /** Parses one or more X.509 certificates from PEM (concatenated). */
    private static List<X509Certificate> parseX509Chain(String pem) {
        try {
            String normalized = pem.replace("\r", "").trim();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // CertificateFactory can parse multiple certs from one stream if they are DER/PEM.
            try (ByteArrayInputStream in =
                         new ByteArrayInputStream(normalized.getBytes(StandardCharsets.US_ASCII))) {

                @SuppressWarnings("unchecked")
                Collection<? extends Certificate> certs =
                        (Collection<? extends Certificate>) cf.generateCertificates(in);

                return certs.stream()
                        .filter(c -> c instanceof X509Certificate)
                        .map(c -> (X509Certificate) c)
                        .toList();
            }
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Invalid X.509 certificate chain PEM", e);
        } catch (IOException e) {
            // ByteArrayInputStream doesn't throw in practice, but keep it clean
            throw new IllegalStateException("Unexpected IO error while parsing certificate chain", e);
        }
    }

    /**
     * Extracts the base64 content between:
     * -----BEGIN {type}----- and -----END {type}-----
     */
    private static String extractPemBlock(String pem, String type) {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";

        int beginIdx = pem.indexOf(begin);
        int endIdx = pem.indexOf(end);

        if (beginIdx < 0 || endIdx < 0 || endIdx <= beginIdx) {
            throw new IllegalArgumentException("PEM block not found: " + type);
        }

        String base64 = pem.substring(beginIdx + begin.length(), endIdx)
                .replace("\n", "")
                .trim();

        if (base64.isEmpty()) {
            throw new IllegalArgumentException("Empty PEM block: " + type);
        }
        return base64;
    }
}