package es.in2.issuer.backend.signing.infrastructure.adapter;

import java.security.*;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

@Slf4j
public class InMemorySigningProvider implements SigningProvider {

    private final ECPrivateKey privateKey;

    //TODO: This is a simple in-memory implementation for development/testing. It generates a new ephemeral EC P-256 keypair on startup.
    public InMemorySigningProvider() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();

            ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
            this.privateKey = (ECPrivateKey) kp.getPrivate();

            log.info("InMemorySigningProvider initialized with ephemeral EC P-256 keypair.");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to initialize InMemorySigningProvider (EC P-256)", e);
        }
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

    /**
     * Creates a real JWS Compact Serialization using ES256:
     *   base64url(header).base64url(payload).base64url(signature)
     *
     * NOTE: This is still "in-memory/dev" because the key is ephemeral and not backed by HSM/QTSP.
     */
    private String signAsJwsEs256(String payloadJson) {
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";

        String headerB64u = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64u = base64Url(payloadJson.getBytes(StandardCharsets.UTF_8));

        String signingInput = headerB64u + "." + payloadB64u;

        byte[] derSignature = ecdsaSignDer(signingInput.getBytes(StandardCharsets.US_ASCII));

        byte[] jwsSignature = derToJoseRs(derSignature, 32);

        String sigB64u = base64Url(jwsSignature);
        return signingInput + "." + sigB64u;
    }

    private byte[] ecdsaSignDer(byte[] signingInput) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(privateKey);
            sig.update(signingInput);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign with in-memory ES256 key", e);
        }
    }

    /**
     * Converts DER ECDSA signature to JOSE (R||S) fixed-size format.
     * @param derSig DER encoded signature (ASN.1 SEQUENCE of two INTEGERs)
     * @param partLen length in bytes of each part (32 for P-256)
     */
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
        if ((b & 0x80) == 0) return b; // short form
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

    /**
     * For COSE in this project’s current SPI shape:
     * - keep returning "Base64 of bytes" so downstream can decode/compress/base45.
     * - This is NOT a real COSE_Sign1 signature.
     */
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