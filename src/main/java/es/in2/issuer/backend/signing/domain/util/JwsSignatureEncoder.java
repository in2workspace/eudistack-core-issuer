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
    private static final int DER_TAG_INTEGER = 0x02;
    private static final int DER_LENGTH_LONG_FORM_ONE_OCTET = 0x81;
    private static final int DER_LENGTH_SHORT_FORM_MAX = 0x7F;

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
        if (isDerEncodedEcdsaSignature(signature)) {
            try {
                // Nimbus sizes its output from the widest INTEGER it finds rather than from
                // outputLength, so an R or S wider than the curve's field yields a concat
                // signature longer than the algorithm allows. Verify before trusting it.
                byte[] concatSignature = ECDSA.transcodeSignatureToConcat(signature, concatLength);
                if (concatSignature.length == concatLength) {
                    return concatSignature;
                }
                log.debug("DER-framed ECDSA signature transcoded to {} bytes, expected {}",
                        concatSignature.length, concatLength);
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
     * Recognizes a complete ASN.1 DER {@code SEQUENCE { INTEGER r, INTEGER s }} spanning exactly
     * the buffer. Both INTEGER headers are validated, not just the outer SEQUENCE: Nimbus reads
     * the inner lengths without bounds-checking them, so handing it a buffer whose declared
     * lengths overrun the array raises ArrayIndexOutOfBoundsException instead of the
     * JOSEException the caller expects.
     *
     * ECDSA signatures use the short length form up to P-384 and the single-octet long form
     * (0x81) for P-521, so no other length encoding needs handling.
     */
    private static boolean isDerEncodedEcdsaSignature(byte[] signature) {
        if (signature.length < 2 || (signature[0] & 0xFF) != DER_TAG_SEQUENCE) {
            return false;
        }

        int firstLengthOctet = signature[1] & 0xFF;
        final int contentOffset;
        final int contentLength;
        if (firstLengthOctet == DER_LENGTH_LONG_FORM_ONE_OCTET) {
            if (signature.length < 3) {
                return false;
            }
            contentOffset = 3;
            contentLength = signature[2] & 0xFF;
        } else if (firstLengthOctet > DER_LENGTH_SHORT_FORM_MAX) {
            return false;
        } else {
            contentOffset = 2;
            contentLength = firstLengthOctet;
        }

        if (signature.length != contentOffset + contentLength) {
            return false;
        }

        int rLength = integerLengthAt(signature, contentOffset);
        if (rLength < 0) {
            return false;
        }
        int sLength = integerLengthAt(signature, contentOffset + 2 + rLength);
        if (sLength < 0) {
            return false;
        }

        return contentLength == 2 + rLength + 2 + sLength;
    }

    /** Length of the DER INTEGER starting at {@code offset}, or -1 if there is no valid one. */
    private static int integerLengthAt(byte[] signature, int offset) {
        if (offset + 1 >= signature.length || (signature[offset] & 0xFF) != DER_TAG_INTEGER) {
            return -1;
        }
        int length = signature[offset + 1] & 0xFF;
        if (length == 0 || length > DER_LENGTH_SHORT_FORM_MAX || offset + 2 + length > signature.length) {
            return -1;
        }
        return length;
    }
}
