package es.in2.issuer.backend.signing.infrastructure.csc;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * Detects whether a signing certificate qualifies as a QSeal per ETSI EN 319 411-2.
 * Only QCP-l-qscd (0.4.0.194112.1.4) yields a qualified seal: a qualified electronic
 * seal under eIDAS requires the private key to reside on a QSCD.
 * QCP-l (0.4.0.194112.1.3, legal person but without QSCD) and any other policy
 * (or no policy extension) yield an AdESeal.
 */
@Slf4j
public final class CertificateQualificationUtils {

    private static final String QCP_L_QSCD = "0.4.0.194112.1.4";
    private static final String CERTIFICATE_POLICIES_OID = "2.5.29.32";

    private CertificateQualificationUtils() {}

    public static boolean isQualifiedSeal(List<String> base64Certs) {
        if (base64Certs == null || base64Certs.isEmpty()) return false;
        try {
            byte[] der = Base64.getDecoder().decode(base64Certs.get(0));
            X509Certificate x509 = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            byte[] extValue = x509.getExtensionValue(CERTIFICATE_POLICIES_OID);
            if (extValue == null) return false;
            ASN1OctetString oct = ASN1OctetString.getInstance(extValue);
            CertificatePolicies policies = CertificatePolicies.getInstance(
                    ASN1Sequence.getInstance(oct.getOctets()));
            for (PolicyInformation pi : policies.getPolicyInformation()) {
                String oid = pi.getPolicyIdentifier().getId();
                if (QCP_L_QSCD.equals(oid)) return true;
            }
        } catch (Exception e) {
            log.warn("Could not determine certificate qualification level: {}", e.getMessage());
        }
        return false;
    }
}
