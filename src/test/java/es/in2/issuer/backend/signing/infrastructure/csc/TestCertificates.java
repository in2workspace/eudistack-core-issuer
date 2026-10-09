package es.in2.issuer.backend.signing.infrastructure.csc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

/**
 * Generates self-signed X.509 certificates (Base64 DER) for CSC certificate tests.
 */
public final class TestCertificates {

    public static final String QCP_L_QSCD = "0.4.0.194112.1.4";
    public static final String QCP_L = "0.4.0.194112.1.3";
    public static final BigInteger SERIAL = new BigInteger("0A1B2C", 16);

    private TestCertificates() {
    }

    /**
     * @param policyOids certificate policy OIDs to include; none means no certificatePolicies extension
     */
    public static String base64Cert(String subject, String... policyOids) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            KeyPair keyPair = generator.generateKeyPair();
            X500Name name = new X500Name(subject);
            Date now = new Date();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    name, SERIAL, now, new Date(now.getTime() + 86_400_000L), name, keyPair.getPublic());
            if (policyOids.length > 0) {
                PolicyInformation[] policies = new PolicyInformation[policyOids.length];
                for (int i = 0; i < policyOids.length; i++) {
                    policies[i] = new PolicyInformation(new ASN1ObjectIdentifier(policyOids[i]));
                }
                builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(policies));
            }
            var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
            return Base64.getEncoder().encodeToString(cert.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException("Could not generate test certificate", e);
        }
    }
}
