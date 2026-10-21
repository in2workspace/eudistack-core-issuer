package es.in2.issuer.backend.signing.domain.util;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Verifies an ES256 JWS signature against the public key of an X.509 certificate.
 *
 * Proves that a signature produced by an external signer (KMS, QTSP) validates with the
 * certificate the issuer would publish in the credential's {@code x5c}, before that certificate
 * is trusted. The signature must already be in the RFC 7518 section 3.4 {@code R || S} form that
 * {@link JwsSignatureEncoder} produces. JCA verifies ECDSA over ASN.1 DER only, so the
 * signature is converted back to {@code SEQUENCE { INTEGER r, INTEGER s }} before verification.
 */
public final class Es256SignatureVerifier {

    private static final int FIELD_LENGTH = 32;
    private static final int ES256_SIGNATURE_LENGTH = 2 * FIELD_LENGTH;
    private static final int DER_TAG_SEQUENCE = 0x30;
    private static final int DER_TAG_INTEGER = 0x02;

    private Es256SignatureVerifier() {}

    /**
     * @param signingInput    the JWS signing input, {@code base64url(header) + "." + base64url(payload)}
     * @param concatSignature the 64-byte {@code R || S} signature
     * @param certificate     certificate carrying the verification key
     * @return {@code true} only if the certificate holds a P-256 key and the signature is valid;
     *         a non-EC or non-P-256 key, a wrong length or an invalid signature yield {@code false}
     * @throws IllegalArgumentException if any argument is null
     */
    public static boolean verify(String signingInput, byte[] concatSignature, X509Certificate certificate) {
        if (signingInput == null || concatSignature == null || certificate == null) {
            throw new IllegalArgumentException("Signing input, signature and certificate are required");
        }
        if (concatSignature.length != ES256_SIGNATURE_LENGTH || !SigningCertificateChecks.isP256(certificate)) {
            return false;
        }
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initVerify(certificate.getPublicKey());
            ecdsa.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return ecdsa.verify(toDer(concatSignature));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** {@code R || S} to {@code SEQUENCE { INTEGER r, INTEGER s }}, each INTEGER minimal and non-negative. */
    private static byte[] toDer(byte[] concatSignature) {
        byte[] r = new BigInteger(1, Arrays.copyOfRange(concatSignature, 0, FIELD_LENGTH)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(concatSignature, FIELD_LENGTH, ES256_SIGNATURE_LENGTH))
                .toByteArray();
        // At most 2 * (2 + 33) octets, so the SEQUENCE length always fits the short form.
        ByteArrayOutputStream der = new ByteArrayOutputStream();
        der.write(DER_TAG_SEQUENCE);
        der.write(2 + r.length + 2 + s.length);
        der.write(DER_TAG_INTEGER);
        der.write(r.length);
        der.writeBytes(r);
        der.write(DER_TAG_INTEGER);
        der.write(s.length);
        der.writeBytes(s);
        return der.toByteArray();
    }
}
