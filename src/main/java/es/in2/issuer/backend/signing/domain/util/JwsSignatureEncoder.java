package es.in2.issuer.backend.signing.domain.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSA;

import java.util.Base64;

/**
 * Normalizes the signature value a QTSP returns from CSC {@code signatures/signHash}
 * into the encoding RFC 7518 mandates for the third JWS segment.
 *
 * Two normalizations are applied:
 * <ul>
 *   <li><b>ECDSA transcoding.</b> A CSC QTSP signs with the raw PKCS#11 primitive and returns
 *       the ASN.1 DER {@code SEQUENCE {r, s}} that ECDSA natively produces. RFC 7518 §3.4
 *       requires the fixed-length {@code R || S} concatenation instead, which is what every
 *       JOSE verifier (Nimbus {@code ECDSAVerifier} included) decodes. Appending the DER blob
 *       verbatim yields a JWS whose signature no conformant reader can validate.</li>
 *   <li><b>Base64 alphabet.</b> Some QTSPs answer in standard Base64; the JWS segment must be
 *       base64url without padding.</li>
 * </ul>
 *
 * RSA signatures need no transcoding — PKCS#1 output is already the raw octet string.
 */
public final class JwsSignatureEncoder {

    private JwsSignatureEncoder() {}

    /**
     * @param qtspSignature signature as returned by the QTSP, Base64 or base64url encoded
     * @param alg           the {@code alg} of the JWS being assembled
     * @return the base64url-encoded signature to use as the third JWS segment
     */
    public static String toJoseSignature(String qtspSignature, JWSAlgorithm alg) {
        if (qtspSignature == null || qtspSignature.isBlank()) {
            throw new IllegalArgumentException("QTSP signature is null or blank");
        }
        if (alg == null) {
            throw new IllegalArgumentException("JWS algorithm is required to normalize the signature");
        }

        byte[] raw = decodeAnyBase64(qtspSignature.trim());

        if (JWSAlgorithm.Family.EC.contains(alg)) {
            raw = toConcatSignature(raw, alg);
        }

        return Base64UrlUtils.encode(raw);
    }

    /**
     * Accepts both Base64 alphabets: {@code +} and {@code /} cannot occur in base64url,
     * so rewriting them is unambiguous.
     */
    private static byte[] decodeAnyBase64(String value) {
        String base64Url = value
                .replace('+', '-')
                .replace('/', '_')
                .replace("=", "");
        try {
            return Base64.getUrlDecoder().decode(base64Url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("QTSP signature is not valid Base64: " + e.getMessage(), e);
        }
    }

    private static byte[] toConcatSignature(byte[] signature, JWSAlgorithm alg) {
        try {
            int concatLength = ECDSA.getSignatureByteArrayLength(alg);

            // Already R || S: a QTSP that returns JOSE-encoded ECDSA needs no transcoding.
            if (signature.length == concatLength) {
                return signature;
            }

            return ECDSA.transcodeSignatureToConcat(signature, concatLength);
        } catch (JOSEException e) {
            throw new IllegalStateException(
                    "QTSP returned a %d-byte ECDSA signature that is neither DER nor %s R||S: %s"
                            .formatted(signature.length, alg.getName(), e.getMessage()), e);
        }
    }
}
