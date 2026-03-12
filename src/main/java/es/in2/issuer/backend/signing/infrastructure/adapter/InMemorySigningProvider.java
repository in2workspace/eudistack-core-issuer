package es.in2.issuer.backend.signing.infrastructure.adapter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * In-memory signing provider backed by a certificate (X.509) and private key loaded from PEM files.
 * <p>
 * A valid certificate is REQUIRED. Without it, credential signing cannot produce the {@code x5c}
 * JOSE header mandated by HAIP for JAdES credentials.
 * <p>
 * Supports both RSA and EC private keys. The signing algorithm is determined by the key type:
 * <ul>
 *     <li>RSA key → RS256 with x5c header</li>
 *     <li>EC key → ES256 with x5c header</li>
 * </ul>
 */
@Slf4j
public class InMemorySigningProvider implements SigningProvider {

    private static final ObjectMapper HEADER_MAPPER = new ObjectMapper();

    private final PrivateKey privateKey;
    private final String signatureAlgorithm;
    private final String jwsAlgorithm;
    private final int signaturePartLen;
    private final String x5cBase64;

    /**
     * Creates an InMemorySigningProvider with a certificate and private key.
     *
     * @param certPath path to the X.509 certificate PEM file
     * @param keyPath  path to the private key PEM file (PKCS#8)
     * @throws IllegalStateException if the certificate or key cannot be loaded
     */
    public InMemorySigningProvider(String certPath, String keyPath) {
        try {
            this.x5cBase64 = loadCertificateAsBase64(certPath);
            PrivateKey loadedKey = loadPrivateKey(keyPath);
            this.privateKey = loadedKey;

            if (loadedKey instanceof RSAPrivateKey) {
                this.signatureAlgorithm = "SHA256withRSA";
                this.jwsAlgorithm = "RS256";
                this.signaturePartLen = 0;
                log.info("InMemorySigningProvider initialized with RSA key + x509 certificate from: {}", certPath);
            } else if (loadedKey instanceof ECPrivateKey) {
                this.signatureAlgorithm = "SHA256withECDSA";
                this.jwsAlgorithm = "ES256";
                this.signaturePartLen = 32;
                log.info("InMemorySigningProvider initialized with EC key + x509 certificate from: {}", certPath);
            } else {
                throw new IllegalStateException("Unsupported private key type: " + loadedKey.getAlgorithm());
            }
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to initialize InMemorySigningProvider: a valid X.509 certificate and private key are required. " +
                    "Configure signing.certificate.cert-path and signing.certificate.key-path. Error: " + e.getMessage(), e);
        }
    }

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            SigningRequestValidator.validate(request);

            String typValue = request.typ() != null ? request.typ() : "JWT";
            return switch (request.type()) {
                case JADES -> Mono.just(new SigningResult(SigningType.JADES, signAsJws(request.data(), typValue)));
                case COSE -> Mono.just(new SigningResult(SigningType.COSE, normalizeBase64(request.data())));
            };
        });
    }

    // ── JWS signing (with x5c certificate) ─────────────────────────────────

    private String buildJwsHeader(String typ) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", jwsAlgorithm);
        header.put("typ", typ);
        header.put("x5c", List.of(x5cBase64));
        try {
            return HEADER_MAPPER.writeValueAsString(header);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize JWS header", e);
        }
    }

    private String signAsJws(String payloadJson, String typ) {
        String headerJson = buildJwsHeader(typ);
        String headerB64u = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64u = base64Url(payloadJson.getBytes(StandardCharsets.UTF_8));

        String signingInput = headerB64u + "." + payloadB64u;

        byte[] rawSignature = signBytes(signingInput.getBytes(StandardCharsets.US_ASCII));

        byte[] jwsSignature;
        if (signaturePartLen > 0) {
            jwsSignature = derToJoseRs(rawSignature, signaturePartLen);
        } else {
            jwsSignature = rawSignature;
        }

        String sigB64u = base64Url(jwsSignature);
        return signingInput + "." + sigB64u;
    }

    private byte[] signBytes(byte[] signingInput) {
        try {
            Signature sig = Signature.getInstance(signatureAlgorithm);
            sig.initSign(privateKey);
            sig.update(signingInput);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign with " + jwsAlgorithm + " key", e);
        }
    }

    // ── DER to JOSE conversion (for ECDSA) ─────────────────────────────────

    private static byte[] derToJoseRs(byte[] derSig, int partLen) {
        if (derSig == null || derSig.length < 8 || derSig[0] != 0x30) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature");
        }

        int idx = 1;
        idx += derLenBytesCount(derSig[idx]);

        if (idx >= derSig.length || derSig[idx] != 0x02) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature (no r)");
        }
        idx++;
        int rLen = derReadLen(derSig, idx);
        idx += derLenBytesCount(derSig[idx]);
        byte[] r = new byte[rLen];
        System.arraycopy(derSig, idx, r, 0, rLen);
        idx += rLen;

        if (idx >= derSig.length || derSig[idx] != 0x02) {
            throw new IllegalArgumentException("Invalid DER ECDSA signature (no s)");
        }
        idx++;
        int sLen = derReadLen(derSig, idx);
        idx += derLenBytesCount(derSig[idx]);
        byte[] s = new byte[sLen];
        System.arraycopy(derSig, idx, s, 0, sLen);

        byte[] jose = new byte[partLen * 2];
        leftPadTrimTo(r, jose, 0, partLen);
        leftPadTrimTo(s, jose, partLen, partLen);
        return jose;
    }

    private static int derReadLen(byte[] der, int idx) {
        int b = der[idx] & 0xFF;
        if ((b & 0x80) == 0) return b;
        int numBytes = b & 0x7F;
        int len = 0;
        for (int i = 1; i <= numBytes; i++) {
            len = (len << 8) | (der[idx + i] & 0xFF);
        }
        return len;
    }

    private static int derLenBytesCount(int firstLenByte) {
        int b = firstLenByte & 0xFF;
        if ((b & 0x80) == 0) return 1;
        return 1 + (b & 0x7F);
    }

    private static void leftPadTrimTo(byte[] src, byte[] dest, int destOff, int len) {
        int start = 0;
        while (start < src.length - 1 && src[start] == 0x00) start++;
        int srcLen = src.length - start;

        if (srcLen > len) {
            start = src.length - len;
            srcLen = len;
        }

        int pad = len - srcLen;
        for (int i = 0; i < pad; i++) dest[destOff + i] = 0x00;
        System.arraycopy(src, start, dest, destOff + pad, srcLen);
    }

    // ── Shared utilities ─────────────────────────────────────────────────────

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String normalizeBase64(String inputBase64) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(inputBase64);
        } catch (IllegalArgumentException ex) {
            log.warn("COSE input was not valid Base64; using raw UTF-8 bytes. reason={}", ex.getMessage());
            bytes = inputBase64.getBytes(StandardCharsets.UTF_8);
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    // ── PEM file loaders ─────────────────────────────────────────────────────

    private static PrivateKey loadPrivateKey(String keyPath) throws IOException, GeneralSecurityException {
        String pem = Files.readString(Path.of(keyPath));
        String base64Key = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        try {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        } catch (GeneralSecurityException ignored) {
            // Not an EC key, try RSA
        }
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static String loadCertificateAsBase64(String certPath) throws IOException, CertificateException {
        byte[] certPem = Files.readAllBytes(Path.of(certPath));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certPem));
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }
}
