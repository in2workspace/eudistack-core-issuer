package es.in2.issuer.backend.signing.domain.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

/**
 * In-memory test PKI for own-key signing tests: nothing is read from or written to disk and no
 * key material is versioned. Every instance generates a fresh root CA and its leaves.
 * All names are fictitious.
 */
final class OwnKeyTestPki {

    static final String ORGANIZATION_IDENTIFIER = "VATES-Q0000000X";

    /** A certificate together with the key pair it was issued for. */
    record Leaf(X509Certificate certificate, KeyPair keyPair) {
        byte[] publicKeyDer() {
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

    OwnKeyTestPki() {
        try {
            rootKeyPair = generateEc();
            rootCertificate = issue(name("Raiz de pruebas"), rootKeyPair, name("Raiz de pruebas"),
                    rootKeyPair.getPublic(), "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
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

    X509Certificate rootCertificate() {
        return rootCertificate;
    }

    /** P-256 leaf issued by the root, valid until 2099. */
    Leaf validP256Leaf() {
        return validP256Leaf;
    }

    /** RSA-2048 leaf issued by the root. */
    Leaf rsaLeaf() {
        return rsaLeaf;
    }

    /** P-384 leaf issued by the root. */
    Leaf p384Leaf() {
        return p384Leaf;
    }

    /** P-256 leaf valid only on 2025-01-01..2025-01-02. */
    Leaf expiredLeaf() {
        return expiredLeaf;
    }

    /** P-256 certificate that names itself as issuer and is signed with its own key. */
    Leaf selfSignedLeaf() {
        return selfSignedLeaf;
    }

    /** SPKI DER of a P-256 key that does not belong to {@link #validP256Leaf()}. */
    byte[] unrelatedPublicKeyDer() {
        return unrelatedP256KeyPair.getPublic().getEncoded();
    }

    /** A leaf whose issuer name matches the root but whose signature was made by another key. */
    X509Certificate forgedSelfIssuedCertificate() {
        try {
            KeyPair attacker = generateEc();
            X500Name subject = name("Raiz de pruebas");
            return issue(subject, attacker, subject, generateEc().getPublic(),
                    "2024-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
        } catch (Exception e) {
            throw new IllegalStateException("Could not build the forged certificate", e);
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
        var builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.nanoTime()),
                Date.from(Instant.parse(notBefore)),
                Date.from(Instant.parse(notAfter)),
                subject,
                subjectKey);
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
