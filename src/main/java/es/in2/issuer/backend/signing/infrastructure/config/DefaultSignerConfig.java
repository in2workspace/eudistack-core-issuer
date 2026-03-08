package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.domain.model.port.SignerConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;


import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Extracts signer identity from the X.509 eSeal certificate Subject DN.
 * This ensures the issuer metadata in credentials always matches the signing certificate,
 * eliminating the need for separate manual configuration.
 */
@Slf4j
@Configuration
public class DefaultSignerConfig implements SignerConfig {

    private static final ASN1ObjectIdentifier OID_ORGANIZATION_IDENTIFIER =
            new ASN1ObjectIdentifier("2.5.4.97");

    private final String organizationIdentifier;
    private final String organization;
    private final String country;
    private final String commonName;
    private final String serialNumber;

    public DefaultSignerConfig(@Value("${signing.certificate.cert-path:}") String certPath) {
        if (certPath == null || certPath.isBlank()) {
            throw new IllegalStateException(
                    "signing.certificate.cert-path is required to extract signer identity from the eSeal certificate.");
        }

        try (InputStream is = new FileInputStream(certPath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
            X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName("RFC2253"));

            this.organizationIdentifier = getFirstRdnValue(x500Name, OID_ORGANIZATION_IDENTIFIER);
            this.organization = getFirstRdnValue(x500Name, BCStyle.O);
            this.country = getFirstRdnValue(x500Name, BCStyle.C);
            this.commonName = getFirstRdnValue(x500Name, BCStyle.CN);
            this.serialNumber = getFirstRdnValue(x500Name, BCStyle.SERIALNUMBER);

            if (this.organizationIdentifier == null || this.organizationIdentifier.isBlank()) {
                throw new IllegalStateException(
                        "Certificate at " + certPath + " does not contain organizationIdentifier (OID 2.5.4.97).");
            }

            log.info("Signer identity extracted from certificate: orgId={}, org={}, CN={}, C={}, serial={}",
                    this.organizationIdentifier, this.organization, this.commonName, this.country, this.serialNumber);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read signer identity from certificate: " + certPath, e);
        }
    }

    @Override
    public String getOrganizationIdentifier() {
        return organizationIdentifier;
    }

    @Override
    public String getOrganization() {
        return organization;
    }

    @Override
    public String getCountry() {
        return country;
    }

    @Override
    public String getCommonName() {
        return commonName;
    }

    @Override
    public String getSerialNumber() {
        return serialNumber;
    }

    private static String getFirstRdnValue(X500Name name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns.length == 0) {
            return null;
        }
        // IETFUtils.valueToString() escapes special characters (e.g. commas → \,).
        // We use the raw ASN.1 string value to get the unescaped form.
        return rdns[0].getFirst().getValue().toString();
    }
}
