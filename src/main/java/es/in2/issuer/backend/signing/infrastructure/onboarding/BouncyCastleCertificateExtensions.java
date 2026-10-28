package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.spi.CertificateExtensionsPort;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/** {@link CertificateExtensionsPort} with BouncyCastle's ASN.1 parser. */
public class BouncyCastleCertificateExtensions implements CertificateExtensionsPort {

    private static final String CERTIFICATE_POLICIES_OID = "2.5.29.32";
    private static final String QC_STATEMENTS_OID = "1.3.6.1.5.5.7.1.3";

    @Override
    public Set<String> policyIdentifiers(X509Certificate certificate) {
        ASN1Sequence policies = extensionValue(certificate, CERTIFICATE_POLICIES_OID);
        if (policies == null) {
            return Set.of();
        }
        return Arrays.stream(CertificatePolicies.getInstance(policies).getPolicyInformation())
                .map(PolicyInformation::getPolicyIdentifier)
                .map(ASN1ObjectIdentifier::getId)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @Override
    public Set<String> qcStatementIdentifiers(X509Certificate certificate) {
        ASN1Sequence statements = extensionValue(certificate, QC_STATEMENTS_OID);
        if (statements == null) {
            return Set.of();
        }
        Set<String> identifiers = new LinkedHashSet<>();
        for (var statement : statements) {
            if (ASN1Sequence.getInstance(statement).getObjectAt(0) instanceof ASN1ObjectIdentifier identifier) {
                identifiers.add(identifier.getId());
            }
        }
        return identifiers;
    }

    @Override
    public Optional<String> organizationIdentifier(X509Certificate certificate) {
        RDN[] rdns = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded())
                .getRDNs(BCStyle.ORGANIZATION_IDENTIFIER);
        return rdns.length == 0 ? Optional.empty() : Optional.of(IETFUtils.valueToString(rdns[0].getFirst().getValue()));
    }

    /** The extension value as an ASN.1 sequence ({@code getExtensionValue} wraps it in an OCTET STRING), or {@code null}. */
    private static ASN1Sequence extensionValue(X509Certificate certificate, String oid) {
        byte[] value = certificate.getExtensionValue(oid);
        return value == null ? null : ASN1Sequence.getInstance(ASN1OctetString.getInstance(value).getOctets());
    }
}
