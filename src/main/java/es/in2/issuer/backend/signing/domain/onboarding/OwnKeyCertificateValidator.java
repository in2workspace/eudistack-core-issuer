package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.util.SigningCertificateChecks;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * The checks an own-key certificate chain must pass before anything is created in KMS (PRD §3.3, AC-12,
 * AC-13). Every failure is an {@link OnboardingRejectedException} with its reason. Nothing here touches
 * KMS or the database; the checks that need them (tenant, reserved SPKI) are made by
 * {@link OwnKeyOnboarding}.
 *
 * <p>The trust anchor is only checked when the policy carries one (always in production): trust in the
 * chain by signature is tech-debt 9 (EUD-264) and is out of scope.
 */
@Slf4j
public final class OwnKeyCertificateValidator {

    /** QCP-n-qscd and QCP-l-qscd (ETSI EN 319 411-2): the certificate states that its key is in a QSCD. */
    private static final Set<String> QSCD_POLICIES = Set.of("0.4.0.194112.1.2", "0.4.0.194112.1.3");
    /** QcSSCD statement inside {@code qcStatements} (ETSI EN 319 412-5): the key is in a QSCD. */
    private static final ASN1ObjectIdentifier QC_SSCD = new ASN1ObjectIdentifier("0.4.0.1862.1.4");
    private static final String CERTIFICATE_POLICIES_OID = "2.5.29.32";
    private static final String QC_STATEMENTS_OID = "1.3.6.1.5.5.7.1.3";
    private static final String EMPTY_CHAIN = "the certificate chain holds no certificate";

    private OwnKeyCertificateValidator() {}

    /** Parses a PEM bundle, leaf first; the chain stored for a tenant is exactly this list. */
    public static List<X509Certificate> parsePemChain(String pem) {
        try {
            var certificates = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            List<X509Certificate> chain = certificates.stream().map(X509Certificate.class::cast).toList();
            if (chain.isEmpty()) {
                throw invalidCertificate(EMPTY_CHAIN);
            }
            return chain;
        } catch (CertificateException _) {
            throw invalidCertificate("the certificate chain cannot be read as PEM X.509 certificates");
        }
    }

    /** Parses the base64 DER certificates of a stored chain, leaf first. */
    public static List<X509Certificate> parseBase64Chain(List<String> base64Der) {
        if (base64Der == null || base64Der.isEmpty()) {
            throw invalidCertificate(EMPTY_CHAIN);
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return base64Der.stream().map(der -> parse(factory, der)).toList();
        } catch (CertificateException _) {
            throw invalidCertificate("the certificate chain cannot be read");
        }
    }

    private static X509Certificate parse(CertificateFactory factory, String base64Der) {
        try {
            return (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(Base64.getDecoder().decode(base64Der)));
        } catch (CertificateException | IllegalArgumentException _) {
            throw invalidCertificate("the certificate chain cannot be read");
        }
    }

    /**
     * @param chain  leaf first, root excluded
     * @param policy the environment-dependent checks
     * @param now    the instant the validity is checked at
     * @throws OnboardingRejectedException with the first check that fails
     */
    public static ValidatedOwnKeyCertificate validate(List<X509Certificate> chain, OnboardingPolicy policy, Instant now) {
        if (chain == null || chain.isEmpty()) {
            throw invalidCertificate(EMPTY_CHAIN);
        }
        X509Certificate leaf = chain.getFirst();
        if (!SigningCertificateChecks.isP256(leaf)) {
            throw new OnboardingRejectedException(RejectionReason.INVALID_KEY,
                    "the certificate key is not an EC P-256 key");
        }
        requireEndEntityForSigning(leaf);
        requireNoQscdDeclaration(leaf);
        requireLinkedChain(chain, now);
        if (!SigningCertificateChecks.isValidAt(leaf, now)) {
            throw invalidCertificate("the certificate is not valid now");
        }
        requireNotSelfSigned(leaf, policy);
        if (policy.trustAnchor() != null) {
            requireTrustAnchor(chain, policy.trustAnchor(), now);
        }
        if (policy.expectedOrganizationIdentifier() != null) {
            requireOrganizationIdentifier(leaf, policy.expectedOrganizationIdentifier());
        }
        return new ValidatedOwnKeyCertificate(chain);
    }

    private static void requireEndEntityForSigning(X509Certificate leaf) {
        if (!SigningCertificateChecks.isEndEntity(leaf)) {
            throw invalidCertificate("the certificate is a CA certificate (basicConstraints CA:TRUE)");
        }
        if (!SigningCertificateChecks.allowsSigning(leaf)) {
            throw invalidCertificate("the certificate key usage does not allow signing "
                    + "(digitalSignature or nonRepudiation)");
        }
    }

    /** A certificate stating that its key is in a QSCD: KMS is not one, so the seal would not be qualified. */
    private static void requireNoQscdDeclaration(X509Certificate leaf) {
        boolean policyDeclared;
        boolean statementDeclared;
        try {
            policyDeclared = declaresQscdPolicy(leaf);
            statementDeclared = declaresQcSscd(leaf);
        } catch (RuntimeException _) {
            // Fail closed: a certificate whose policies cannot be read cannot be shown not to declare a QSCD.
            throw invalidCertificate("the certificate policies or qcStatements cannot be read");
        }
        if (policyDeclared) {
            throw invalidCertificate("the certificate policy is QCP-n-qscd or QCP-l-qscd (key in a QSCD), "
                    + "but KMS is not a QSCD");
        }
        if (statementDeclared) {
            throw invalidCertificate("the certificate states QcSSCD (key in a QSCD), but KMS is not a QSCD");
        }
    }

    private static boolean declaresQscdPolicy(X509Certificate certificate) {
        ASN1Sequence policies = extensionValue(certificate, CERTIFICATE_POLICIES_OID);
        if (policies == null) {
            return false;
        }
        return Arrays.stream(CertificatePolicies.getInstance(policies).getPolicyInformation())
                .map(PolicyInformation::getPolicyIdentifier)
                .anyMatch(oid -> QSCD_POLICIES.contains(oid.getId()));
    }

    private static boolean declaresQcSscd(X509Certificate certificate) {
        ASN1Sequence statements = extensionValue(certificate, QC_STATEMENTS_OID);
        if (statements == null) {
            return false;
        }
        for (var statement : statements) {
            if (QC_SSCD.equals(ASN1Sequence.getInstance(statement).getObjectAt(0))) {
                return true;
            }
        }
        return false;
    }

    /** The extension value as an ASN.1 sequence ({@code getExtensionValue} wraps it in an OCTET STRING), or {@code null}. */
    private static ASN1Sequence extensionValue(X509Certificate certificate, String oid) {
        byte[] value = certificate.getExtensionValue(oid);
        return value == null ? null : ASN1Sequence.getInstance(ASN1OctetString.getInstance(value).getOctets());
    }

    /** Each certificate is issued by the next, which is a CA valid now; the failing pair is named. */
    private static void requireLinkedChain(List<X509Certificate> chain, Instant now) {
        for (int i = 1; i < chain.size(); i++) {
            X509Certificate issued = chain.get(i - 1);
            X509Certificate issuer = chain.get(i);
            if (SigningCertificateChecks.isLinkedChain(List.of(issued, issuer), now)) {
                continue;
            }
            int position = i + 1;
            if (!SigningCertificateChecks.isValidAt(issuer, now)) {
                throw invalidCertificate(certificateAt(position) + " of the chain is not valid now");
            }
            if (SigningCertificateChecks.isEndEntity(issuer)) {
                throw invalidCertificate(certificateAt(position) + " of the chain is not a CA");
            }
            throw invalidCertificate(certificateAt(i) + " of the chain is not issued by " + certificateAt(position));
        }
    }

    private static String certificateAt(int position) {
        return "certificate " + position;
    }

    private static void requireNotSelfSigned(X509Certificate leaf, OnboardingPolicy policy) {
        if (!SigningCertificateChecks.isSelfSigned(leaf)) {
            return;
        }
        if (policy.production()) {
            throw invalidCertificate("the certificate is self-signed (production)");
        }
        log.warn("The certificate is self-signed: accepted outside production");
    }

    /**
     * The chain ends in the CA agreed with the tenant, which may be the root or an intermediate: the anchor
     * is one of the certificates of the chain or issued one of them, and is a CA valid now.
     */
    private static void requireTrustAnchor(List<X509Certificate> chain, X509Certificate anchor, Instant now) {
        boolean anchored = SigningCertificateChecks.isValidAt(anchor, now)
                && !SigningCertificateChecks.isEndEntity(anchor)
                && chain.stream().anyMatch(certificate -> sameCertificate(certificate, anchor)
                        || SigningCertificateChecks.isLinkedChain(List.of(certificate, anchor), now));
        if (!anchored) {
            throw invalidCertificate("the chain does not end in the agreed CA");
        }
    }

    private static boolean sameCertificate(X509Certificate a, X509Certificate b) {
        try {
            return Arrays.equals(a.getEncoded(), b.getEncoded());
        } catch (CertificateException _) {
            return false;
        }
    }

    private static void requireOrganizationIdentifier(X509Certificate leaf, String expected) {
        String actual = organizationIdentifier(leaf);
        if (!expected.equals(actual)) {
            throw invalidCertificate("the certificate organizationIdentifier is '"
                    + (actual == null ? "none" : actual) + "', expected '" + expected + "'");
        }
    }

    private static String organizationIdentifier(X509Certificate certificate) {
        RDN[] rdns = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded())
                .getRDNs(BCStyle.ORGANIZATION_IDENTIFIER);
        return rdns.length == 0 ? null : IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

    private static OnboardingRejectedException invalidCertificate(String message) {
        return new OnboardingRejectedException(RejectionReason.INVALID_CERTIFICATE, message);
    }
}
