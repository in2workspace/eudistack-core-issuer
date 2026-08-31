package es.in2.issuer.backend.signing.domain.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSA;
import lombok.extern.slf4j.Slf4j;

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
@Slf4j
public final class JwsSignatureEncoder {

    private static final int DER_TAG_SEQUENCE = 0x30;
    private static final int DER_LENGTH_LONG_FORM_ONE_OCTET = 0x81;

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
        int concatLength;
        try {
            concatLength = ECDSA.getSignatureByteArrayLength(alg);
        } catch (JOSEException e) {
            throw new IllegalStateException("Unsupported ECDSA algorithm: " + alg.getName(), e);
        }

        // Length alone cannot separate the two encodings: a DER SEQUENCE whose INTEGERs are
        // short enough can measure exactly concatLength, and conversely the first octet of R
        // in an R||S signature may happen to be 0x30. So test the DER framing structurally
        // and let Nimbus reject the candidate if the inner INTEGERs do not parse.
        if (isDerSequence(signature)) {
            try {
                return ECDSA.transcodeSignatureToConcat(signature, concatLength);
            } catch (JOSEException e) {
                log.debug("ECDSA signature looked DER-framed but did not transcode: {}", e.getMessage());
            }
        }

        // Already R || S: a QTSP that returns JOSE-encoded ECDSA needs no transcoding.
        if (signature.length == concatLength) {
            return signature;
        }

        throw new IllegalStateException(
                "QTSP returned a %d-byte ECDSA signature that is neither DER nor %s R||S"
                        .formatted(signature.length, alg.getName()));
    }

    /**
     * Recognizes an ASN.1 DER {@code SEQUENCE} whose declared length spans exactly the buffer.
     * ECDSA signatures use the short length form up to P-384 and the single-octet long form
     * (0x81) for P-521, so no other length encoding needs handling.
     */
    private static boolean isDerSequence(byte[] signature) {
        if (signature.length < 2 || (signature[0] & 0xFF) != DER_TAG_SEQUENCE) {
            return false;
        }
        int firstLengthOctet = signature[1] & 0xFF;
        if (firstLengthOctet == DER_LENGTH_LONG_FORM_ONE_OCTET) {
            return signature.length >= 3 && signature.length == 3 + (signature[2] & 0xFF);
        }
        if (firstLengthOctet > 0x7F) {
            return false;
        }
        return signature.length == 2 + firstLengthOctet;
    }
}
