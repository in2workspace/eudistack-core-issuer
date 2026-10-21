package es.in2.issuer.backend.signing.domain.util;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.time.Instant;

/**
 * Stateless predicates over an X.509 signing certificate. Each answers one question and
 * reports nothing else; deciding what a failed check means is up to the caller.
 */
public final class SigningCertificateChecks {

    private static final ECParameterSpec SECP256R1 = secp256r1();

    private SigningCertificateChecks() {}

    /** {@code true} if the certificate holds an EC key on P-256; RSA and other curves are {@code false}. */
    public static boolean isP256(X509Certificate certificate) {
        requireCertificate(certificate);
        return certificate.getPublicKey() instanceof ECPublicKey publicKey && isSecp256r1(publicKey.getParams());
    }

    /** ECParameterSpec has no equals(), so the curve, generator, order and cofactor are compared one by one. */
    private static boolean isSecp256r1(ECParameterSpec params) {
        return SECP256R1.getCurve().equals(params.getCurve())
                && SECP256R1.getGenerator().equals(params.getGenerator())
                && SECP256R1.getOrder().equals(params.getOrder())
                && SECP256R1.getCofactor() == params.getCofactor();
    }

    private static ECParameterSpec secp256r1() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("The JDK does not provide secp256r1", e);
        }
    }

    /**
     * {@code true} if subject equals issuer and the signature verifies with the certificate's own key.
     * Matching names alone prove nothing: anyone can issue a certificate that names itself as issuer.
     */
    public static boolean isSelfSigned(X509Certificate certificate) {
        requireCertificate(certificate);
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** {@code true} if {@code at} falls inside the validity window, both bounds inclusive. */
    public static boolean isValidAt(X509Certificate certificate, Instant at) {
        requireCertificate(certificate);
        if (at == null) {
            throw new IllegalArgumentException("Instant is required");
        }
        return !at.isBefore(certificate.getNotBefore().toInstant())
                && !at.isAfter(certificate.getNotAfter().toInstant());
    }

    /**
     * {@code true} if the certificate's public key is the key encoded in {@code spkiDer}
     * (compared by SPKI SHA-256, see {@link PublicKeyFingerprints}).
     *
     * @throws IllegalArgumentException if the certificate is null or {@code spkiDer} is not a valid SPKI
     */
    public static boolean matchesPublicKey(X509Certificate certificate, byte[] spkiDer) {
        requireCertificate(certificate);
        return PublicKeyFingerprints.spkiSha256(certificate)
                .equals(PublicKeyFingerprints.spkiSha256(spkiDer));
    }

    private static void requireCertificate(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate is required");
        }
    }
}
