package es.in2.issuer.backend.signing.domain.util;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.time.Instant;
import java.util.List;

/**
 * Stateless predicates over an X.509 signing certificate. Each answers one question and
 * reports nothing else; deciding what a failed check means is up to the caller.
 */
public final class SigningCertificateChecks {

    private static final ECParameterSpec SECP256R1 = secp256r1();
    private static final int DIGITAL_SIGNATURE = 0;
    private static final int NON_REPUDIATION = 1;

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
        } catch (GeneralSecurityException _) {
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

    /** {@code true} unless the certificate is a CA ({@code basicConstraints} with {@code cA} true): a CA does not sign content. */
    public static boolean isEndEntity(X509Certificate certificate) {
        requireCertificate(certificate);
        return certificate.getBasicConstraints() == -1;
    }

    /**
     * {@code true} if {@code keyUsage} allows {@code digitalSignature} or {@code nonRepudiation}, or is
     * absent (no restriction, RFC 5280 §4.2.1.3).
     */
    public static boolean allowsSigning(X509Certificate certificate) {
        requireCertificate(certificate);
        boolean[] keyUsage = certificate.getKeyUsage();
        return keyUsage == null || keyUsage[DIGITAL_SIGNATURE] || keyUsage[NON_REPUDIATION];
    }

    /**
     * {@code true} if every certificate of the chain (leaf first) is issued by the next one, by name and
     * signature, and every certificate after the leaf is a CA valid at {@code at}. It says nothing about
     * trust: the last certificate is not checked against any trust anchor (tech-debt 9, EUD-264).
     */
    public static boolean isLinkedChain(List<X509Certificate> chain, Instant at) {
        if (chain == null || chain.isEmpty() || at == null) {
            throw new IllegalArgumentException("Chain and instant are required");
        }
        for (int i = 1; i < chain.size(); i++) {
            X509Certificate issued = chain.get(i - 1);
            X509Certificate issuer = chain.get(i);
            requireCertificate(issuer);
            if (issuer.getBasicConstraints() == -1 || !isValidAt(issuer, at)
                    || !issued.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                return false;
            }
            try {
                issued.verify(issuer.getPublicKey());
            } catch (GeneralSecurityException _) {
                return false;
            }
        }
        return true;
    }

    private static void requireCertificate(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate is required");
        }
    }
}
