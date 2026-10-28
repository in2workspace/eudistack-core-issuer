package es.in2.issuer.backend.signing.domain.util;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * In-memory test PKI for own-key signing tests: nothing is read from or written to disk and no
 * key material is versioned. Every instance generates a fresh root CA and its leaves.
 * All names are fictitious.
 */
public final class OwnKeyTestPki {

    public static final String ORGANIZATION_IDENTIFIER = "VATES-Q0000000X";

    /** A chain, leaf first and root excluded, together with the key pair of its leaf. */
    public record Chain(List<X509Certificate> certificates, KeyPair leafKeyPair) {}

    private static final BasicConstraints CA = new BasicConstraints(true);
    private static final BasicConstraints END_ENTITY = new BasicConstraints(false);
    private static final KeyUsage CERT_SIGN = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
    private static final KeyUsage SIGNING = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);

    /** A certificate together with the key pair it was issued for. */
    public record Leaf(X509Certificate certificate, KeyPair keyPair) {
        public byte[] publicKeyDer() {
            return keyPair.getPublic().getEncoded();
        }
    }

    private final KeyPair rootKeyPair;
    private final X509Certificate rootCertificate;
    private final Leaf validP256Leaf;
    private final Leaf rsaLeaf;
    private final Leaf p384Leaf;
    private final Leaf expiredLeaf;
    private final Leaf selfSignedLeaf;
    private final KeyPair unrelatedP256KeyPair;

    public OwnKeyTestPki() {
        try {
            rootKeyPair = generateEc();
            rootCertificate = issue(name("Raiz de pruebas"), rootKeyPair, name("Raiz de pruebas"),
                    rootKeyPair.getPublic(), "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z", CA, CERT_SIGN);
            validP256Leaf = leafSignedByRoot(generateEc(), "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
            rsaLeaf = leafSignedByRoot(generateRsa(), "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
            p384Leaf = leafSignedByRoot(generateEc(384), "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
            expiredLeaf = leafSignedByRoot(generateEc(), "2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z");
            KeyPair selfSignedKeyPair = generateEc();
            selfSignedLeaf = new Leaf(
                    issue(name("Hoja autofirmada"), selfSignedKeyPair, name("Hoja autofirmada"),
                            selfSignedKeyPair.getPublic(), "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
                    selfSignedKeyPair);
            unrelatedP256KeyPair = generateEc();
        } catch (Exception e) {
            throw new IllegalStateException("Could not build the test PKI", e);
        }
    }

    public X509Certificate rootCertificate() {
        return rootCertificate;
    }

    /** P-256 leaf issued by the root, valid until 2099. */
    public Leaf validP256Leaf() {
        return validP256Leaf;
    }

    /** RSA-2048 leaf issued by the root. */
    public Leaf rsaLeaf() {
        return rsaLeaf;
    }

    /** P-384 leaf issued by the root. */
    public Leaf p384Leaf() {
        return p384Leaf;
    }

    /** P-256 leaf valid only on 2025-01-01..2025-01-02. */
    public Leaf expiredLeaf() {
        return expiredLeaf;
    }

    /** P-256 certificate that names itself as issuer and is signed with its own key. */
    public Leaf selfSignedLeaf() {
        return selfSignedLeaf;
    }

    /** SPKI DER of a P-256 key that does not belong to {@link #validP256Leaf()}. */
    public byte[] unrelatedPublicKeyDer() {
        return unrelatedP256KeyPair.getPublic().getEncoded();
    }

    /** A leaf whose issuer name matches the root but whose signature was made by another key. */
    public X509Certificate forgedSelfIssuedCertificate() {
        try {
            KeyPair attacker = generateEc();
            X500Name subject = name("Raiz de pruebas");
            return issue(subject, attacker, subject, generateEc().getPublic(),
                    "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
        } catch (Exception e) {
            throw new IllegalStateException("Could not build the forged certificate", e);
        }
    }

    /** P-256 leaf whose subject and issuer names carry no organizationIdentifier (signed with the root key). */
    public Leaf leafWithoutOrganizationIdentifier() {
        try {
            KeyPair keyPair = generateEc();
            X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.C, "ES")
                    .addRDN(BCStyle.O, "CGCOM PRUEBAS (ficticio)")
                    .addRDN(BCStyle.CN, "Sello sin identificador")
                    .build();
            return new Leaf(issue(subject, rootKeyPair, subject, keyPair.getPublic(),
                    "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z"), keyPair);
        } catch (Exception e) {
            throw new IllegalStateException("Could not build the leaf without organizationIdentifier", e);
        }
    }

    /** A valid leaf certificate issued by the root for an externally held public key (e.g. a KMS key). */
    public X509Certificate certificateFor(java.security.PublicKey publicKey) {
        try {
            return issue(name("Sello de pruebas"), rootKeyPair, name("Raiz de pruebas"), publicKey,
                    "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
        } catch (Exception e) {
            throw new IllegalStateException("Could not issue the certificate", e);
        }
    }

    /** P-256 leaf issued by the root with explicit end-entity extensions (CA:false, digitalSignature, nonRepudiation). */
    public Leaf signingLeafWithExtensions() {
        return leafWithExtensions(END_ENTITY, SIGNING);
    }

    /** P-256 certificate issued by the root that is itself a CA (basicConstraints cA=true). */
    public Leaf caLeaf() {
        return leafWithExtensions(CA, CERT_SIGN);
    }

    /** P-256 end-entity leaf issued by the root whose key usage only allows certificate signing. */
    public Leaf certSignOnlyLeaf() {
        return leafWithExtensions(END_ENTITY, CERT_SIGN);
    }

    /** Leaf issued by an intermediate CA issued by the root; the chain holds the leaf and the intermediate. */
    public Chain chainWithIntermediate() {
        return chainWithIntermediate("2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
    }

    /** Like {@link #chainWithIntermediate()}, but the intermediate was valid only on 2025-01-01..2025-01-02. */
    public Chain chainWithExpiredIntermediate() {
        return chainWithIntermediate("2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z");
    }

    /** P-256 leaf issued by the root that declares the given certificate policy (for example a QCP-n-qscd OID). */
    public Leaf leafWithPolicy(String policyOid) {
        return leafWithExtra(builder -> builder.addExtension(Extension.certificatePolicies, false,
                new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(policyOid)))));
    }

    /** P-256 leaf issued by the root whose qcStatements declare QcSSCD (0.4.0.1862.1.4): the key is in a QSCD. */
    public Leaf leafWithQcSscdStatement() {
        return leafWithExtra(builder -> {
            ASN1EncodableVector statement = new ASN1EncodableVector();
            statement.add(new ASN1ObjectIdentifier("0.4.0.1862.1.4"));
            ASN1EncodableVector statements = new ASN1EncodableVector();
            statements.add(new DERSequence(statement));
            builder.addExtension(Extension.qCStatements, false, new DERSequence(statements));
        });
    }

    /** P-256 leaf issued by the root whose subject carries another organizationIdentifier. */
    public Leaf leafWithOrganizationIdentifier(String organizationIdentifier) {
        try {
            KeyPair keyPair = generateEc();
            X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.C, "ES")
                    .addRDN(BCStyle.O, "OTRA ORGANIZACION (ficticio)")
                    .addRDN(BCStyle.ORGANIZATION_IDENTIFIER, organizationIdentifier)
                    .addRDN(BCStyle.CN, "Sello de pruebas")
                    .build();
            return new Leaf(issue(subject, rootKeyPair, name("Raiz de pruebas"), keyPair.getPublic(),
                    "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z"), keyPair);
        } catch (Exception e) {
            throw new IllegalStateException("Could not issue the leaf", e);
        }
    }

    /** A leaf issued by a certificate that is not a CA (basicConstraints cA=false); the chain is leaf and issuer. */
    public Chain chainWithNonCaIssuer() {
        try {
            KeyPair issuerKeyPair = generateEc();
            X500Name issuerName = name("Emisor que no es CA");
            X509Certificate issuer = issue(issuerName, rootKeyPair, name("Raiz de pruebas"), issuerKeyPair.getPublic(),
                    "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z", END_ENTITY, SIGNING);
            KeyPair leafKeyPair = generateEc();
            X509Certificate leaf = issue(name("Sello de pruebas"), issuerKeyPair, issuerName, leafKeyPair.getPublic(),
                    "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z", END_ENTITY, SIGNING);
            return new Chain(List.of(leaf, issuer), leafKeyPair);
        } catch (Exception e) {
            throw new IllegalStateException("Could not build the chain", e);
        }
    }

    /** Adds extensions to a certificate builder. */
    @FunctionalInterface
    private interface ExtensionAdder {
        void add(JcaX509v3CertificateBuilder builder) throws Exception;
    }

    private Leaf leafWithExtra(ExtensionAdder extra) {
        try {
            KeyPair keyPair = generateEc();
            return new Leaf(issue(name("Sello de pruebas"), rootKeyPair, name("Raiz de pruebas"), keyPair.getPublic(),
                    "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z", END_ENTITY, SIGNING, extra), keyPair);
        } catch (Exception e) {
            throw new IllegalStateException("Could not issue the leaf", e);
        }
    }

    private Chain chainWithIntermediate(String intermediateNotBefore, String intermediateNotAfter) {
        try {
            KeyPair intermediateKeyPair = generateEc();
            X500Name intermediateName = name("Intermedia de pruebas");
            X509Certificate intermediate = issue(intermediateName, rootKeyPair, name("Raiz de pruebas"),
                    intermediateKeyPair.getPublic(), intermediateNotBefore, intermediateNotAfter, CA, CERT_SIGN);
            KeyPair leafKeyPair = generateEc();
            X509Certificate leaf = issue(name("Sello de pruebas"), intermediateKeyPair, intermediateName,
                    leafKeyPair.getPublic(), "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z", END_ENTITY, SIGNING);
            return new Chain(List.of(leaf, intermediate), leafKeyPair);
        } catch (Exception e) {
            throw new IllegalStateException("Could not build the chain", e);
        }
    }

    private Leaf leafWithExtensions(BasicConstraints basicConstraints, KeyUsage keyUsage) {
        try {
            KeyPair keyPair = generateEc();
            return new Leaf(issue(name("Sello de pruebas"), rootKeyPair, name("Raiz de pruebas"), keyPair.getPublic(),
                    "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z", basicConstraints, keyUsage), keyPair);
        } catch (Exception e) {
            throw new IllegalStateException("Could not issue the leaf", e);
        }
    }

    private Leaf leafSignedByRoot(KeyPair leafKeyPair, String notBefore, String notAfter) throws Exception {
        X509Certificate certificate = issue(name("Sello de pruebas"), rootKeyPair, name("Raiz de pruebas"),
                leafKeyPair.getPublic(), notBefore, notAfter);
        return new Leaf(certificate, leafKeyPair);
    }

    private static X509Certificate issue(X500Name subject, KeyPair signer, X500Name issuer,
                                         java.security.PublicKey subjectKey, String notBefore, String notAfter)
            throws Exception {
        return issue(subject, signer, issuer, subjectKey, notBefore, notAfter, null, null);
    }

    /** {@code basicConstraints} and {@code keyUsage} are added (critical) only when not null. */
    private static X509Certificate issue(X500Name subject, KeyPair signer, X500Name issuer,
                                         java.security.PublicKey subjectKey, String notBefore, String notAfter,
                                         BasicConstraints basicConstraints, KeyUsage keyUsage)
            throws Exception {
        return issue(subject, signer, issuer, subjectKey, notBefore, notAfter, basicConstraints, keyUsage, null);
    }

    private static X509Certificate issue(X500Name subject, KeyPair signer, X500Name issuer,
                                         java.security.PublicKey subjectKey, String notBefore, String notAfter,
                                         BasicConstraints basicConstraints, KeyUsage keyUsage, ExtensionAdder extra)
            throws Exception {
        var builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.parse(notBefore)),
                Date.from(Instant.parse(notAfter)),
                subject,
                subjectKey);
        if (basicConstraints != null) {
            builder.addExtension(Extension.basicConstraints, true, basicConstraints);
        }
        if (keyUsage != null) {
            builder.addExtension(Extension.keyUsage, true, keyUsage);
        }
        if (extra != null) {
            extra.add(builder);
        }
        String algorithm = "RSA".equals(signer.getPrivate().getAlgorithm()) ? "SHA256withRSA" : "SHA256withECDSA";
        var contentSigner = new JcaContentSignerBuilder(algorithm).build(signer.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));
    }

    private static X500Name name(String commonName) {
        return new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "ES")
                .addRDN(BCStyle.O, "CGCOM PRUEBAS (ficticio)")
                .addRDN(BCStyle.ORGANIZATION_IDENTIFIER, ORGANIZATION_IDENTIFIER)
                .addRDN(BCStyle.CN, commonName)
                .build();
    }

    private static KeyPair generateEc() throws Exception {
        return generateEc(256);
    }

    private static KeyPair generateEc(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    private static KeyPair generateRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
