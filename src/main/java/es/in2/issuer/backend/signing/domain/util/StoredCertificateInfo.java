package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * Builds the {@link CertificateInfo} that a QTSP would answer from {@code credentials/info}, but
 * from the certificate chain stored for an own-key tenant. Own-key tenants have no QTSP to ask,
 * so the issuer identity and the JAdES header are derived from the same value object as on the
 * QTSP path.
 *
 * <p>Field formats follow the CSC mappers' X.509 fallback: {@code subjectDN}/{@code issuerDN}
 * are RFC 2253 names and {@code serialNumber} is the certificate serial in uppercase hexadecimal
 * (CSC API v2.0 returns it as a hexadecimal string).
 */
public final class StoredCertificateInfo {

    /** ecdsa-with-SHA256; the header builder maps it to {@code ES256}, the only supported algorithm. */
    private static final String ECDSA_SHA256_OID = "1.2.840.10045.4.3.2";
    private static final int P256_KEY_LENGTH = 256;

    private StoredCertificateInfo() {}

    /**
     * @param config        own-key configuration holding the chain, leaf first
     * @param qualifiedSeal whether the leaf is a qualified seal; the caller decides because the
     *                      detection lives in infrastructure
     * @throws SigningException {@code CERTIFICATE_INVALID} if the leaf cannot be parsed
     */
    public static CertificateInfo from(OwnKeySigningConfig config, boolean qualifiedSeal) {
        X509Certificate leaf = leaf(config);
        return new CertificateInfo(
                config.certificateChain(),
                leaf.getIssuerX500Principal().getName(),
                leaf.getSubjectX500Principal().getName(),
                leaf.getSerialNumber().toString(16).toUpperCase(),
                leaf.getNotBefore().toInstant().toString(),
                leaf.getNotAfter().toInstant().toString(),
                List.of(ECDSA_SHA256_OID),
                P256_KEY_LENGTH,
                qualifiedSeal);
    }

    /** The first certificate of the stored chain, parsed. */
    public static X509Certificate leaf(OwnKeySigningConfig config) {
        try {
            byte[] der = Base64.getDecoder().decode(config.certificateChain().getFirst());
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new SigningException(SigningFailureReason.CERTIFICATE_INVALID,
                    "The stored signing certificate cannot be parsed", e);
        }
    }
}
