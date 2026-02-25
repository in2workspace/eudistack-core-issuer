package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
public class InMemorySigningProvider implements SigningProvider {

    private final ECPrivateKey privateKey;
    private final List<X509Certificate> certificateChain; // nullable/empty => no x5c

    /**
     * Fallback constructor: generates ephemeral EC P-256 keypair (dev/test).
     * No x5c will be included in the JWS header.
     */
    public InMemorySigningProvider() {
        this(loadEphemeralKey(), List.of());
        log.info("InMemorySigningProvider initialized with ephemeral EC P-256 keypair (no x5c).");
    }

    /**
     * Provided material constructor (Option A): uses injected private key + cert chain.
     * x5c WILL be included in the JWS header (Base64 DER).
     */
    public InMemorySigningProvider(InMemoryKeyMaterialLoader.KeyMaterial keyMaterial) {
        this(
                Objects.requireNonNull(keyMaterial, "keyMaterial is required").privateKey(),
                keyMaterial.certificateChain()
        );
        log.info("InMemorySigningProvider initialized with PROVIDED key material (x5c enabled). chainSize={}",
                this.certificateChain.size());
    }

    private InMemorySigningProvider(ECPrivateKey privateKey, List<X509Certificate> certificateChain) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey is required");
        this.certificateChain = certificateChain == null ? List.of() : List.copyOf(certificateChain);
    }

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            SigningRequestValidator.validate(request);

            return switch (request.type()) {
                case JADES -> Mono.just(new SigningResult(SigningType.JADES, signAsJwsEs256(request.data())));
                case COSE -> Mono.just(new SigningResult(SigningType.COSE, normalizeBase64(request.data())));
            };
        });
    }

    private String signAsJwsEs256(String payloadJson) {
        String headerJson = buildJoseHeaderJson();

        String headerB64u = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64u = base64Url(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signingInput = headerB64u + "." + payloadB64u;

        byte[] derSignature = ecdsaSignDer(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] jwsSignature = derToJoseRs(derSignature, 32); // P-256 => 32 bytes R + 32 bytes S

        return signingInput + "." + base64Url(jwsSignature);
    }

    /**
     * JOSE header:
     * - Always: alg=ES256, typ=JWT
     * - Optionally: x5c=[Base64(DER(cert0)), Base64(DER(cert1)), ...]
     *
     * Note: x5c uses STANDARD Base64 (not Base64URL).
     */
    private String buildJoseHeaderJson() {
        if (certificateChain.isEmpty()) {
            return "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";
        }

        List<String> x5c = certificateChain.stream()
                .map(this::toX5cBase64Der)
                .toList();

        String x5cJsonArray = x5c.stream()
                .map(s -> "\"" + s + "\"")
                .collect(Collectors.joining(",", "[", "]"));

        return "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"x5c\":" + x5cJsonArray + "}";
    }

    private String toX5cBase64Der(X509Certificate cert) {
        try {
            return Base64.getEncoder().encodeToString(cert.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException("Unable to encode certificate to DER for x5c", e);
        }
    }

    private byte[] ecdsaSignDer(byte[] signingInput) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(privateKey);
            sig.update(signingInput);
            return sig.sign(); // DER
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign with ES256", e);
        }
    }

    private static ECPrivateKey loadEphemeralKey() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            return (ECPrivateKey) kp.getPrivate();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to generate ephemeral EC P-256 keypair", e);
        }
    }

    // --- DER -> JOSE (R||S) conversion helpers (same as your current code, kept) ---

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
}