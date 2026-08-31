package es.in2.issuer.backend.signing.domain.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JadesHeaderBuilderServiceImplTest {

    private ObjectMapper objectMapper;
    private JadesHeaderBuilderServiceImpl sut;

    @BeforeAll
    static void addBcProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        sut = new JadesHeaderBuilderServiceImpl(objectMapper);
    }

    // --------------------------------------------------
    // HAPPY PATH
    // --------------------------------------------------

    @Test
    void buildHeader_jadesBB_containsAlgTypAndX5c_es256() throws Exception {
        CertificateInfo certInfo = certificateInfo(
                List.of("MIIC..."),
                List.of("1.2.840.10045.4.3.2") // ES256
        );

        String json = sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null);

        JsonNode node = objectMapper.readTree(json);

        assertEquals("ES256", node.get("alg").asText());
        assertEquals("JWT", node.get("typ").asText());
        assertTrue(node.get("x5c").isArray());
        assertEquals("MIIC...", node.get("x5c").get(0).asText());
        assertNull(node.get("sigT")); // no timestamp for B_B
    }

    @Test
    void buildHeader_jadesBT_addsSigT() throws Exception {
        CertificateInfo certInfo = certificateInfo(
                List.of("MIIC..."),
                List.of("1.2.840.10045.4.3.2")
        );

        String json = sut.buildHeader(certInfo, JadesProfile.JADES_B_T, null);

        JsonNode node = objectMapper.readTree(json);

        assertEquals("ES256", node.get("alg").asText());
        assertNotNull(node.get("sigT"));

        // Validate ISO-8601 format
        assertDoesNotThrow(() -> Instant.parse(node.get("sigT").asText()));
    }

    @Test
    void buildHeader_withVcJwtTyp_containsVcPlusJwt() throws Exception {
        CertificateInfo certInfo = certificateInfo(
                List.of("MIIC..."),
                List.of("1.2.840.10045.4.3.2") // ES256
        );

        String json = sut.buildHeader(certInfo, JadesProfile.JADES_B_B, "vc+jwt");

        JsonNode node = objectMapper.readTree(json);

        assertEquals("ES256", node.get("alg").asText());
        assertEquals("vc+jwt", node.get("typ").asText());
        assertTrue(node.get("x5c").isArray());
    }

    // --------------------------------------------------
    // OID MAPPING
    // --------------------------------------------------

    @Test
    void buildHeader_mapsOid_es384() throws Exception {
        CertificateInfo certInfo = certificateInfo(
                List.of("CERT"),
                List.of("1.2.840.10045.4.3.3")
        );

        JsonNode node = objectMapper.readTree(
                sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null)
        );

        assertEquals("ES384", node.get("alg").asText());
    }

    @Test
    void buildHeader_mapsOid_es512() throws Exception {
        CertificateInfo certInfo = certificateInfo(
                List.of("CERT"),
                List.of("1.2.840.10045.4.3.4")
        );

        JsonNode node = objectMapper.readTree(
                sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null)
        );

        assertEquals("ES512", node.get("alg").asText());
    }

    @Test
    void buildHeader_mapsGenericRsaEncryptionOid_rs256() throws Exception {
        CertificateInfo certInfo = certificateInfo(
                List.of("CERT"),
                List.of("1.2.840.113549.1.1.1") // rsaEncryption (generic RSA key OID, as Vintegris reports)
        );

        JsonNode node = objectMapper.readTree(
                sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null)
        );

        assertEquals("RS256", node.get("alg").asText());
    }

    @Test
    void buildHeader_mapsGenericEcPublicKeyOid_es256() throws Exception {
        CertificateInfo certInfo = certificateInfo(
                List.of("CERT"),
                List.of("1.2.840.10045.2.1") // id-ecPublicKey (generic EC key OID)
        );

        JsonNode node = objectMapper.readTree(
                sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null)
        );

        assertEquals("ES256", node.get("alg").asText());
    }

    // --------------------------------------------------
    // ERROR CASES
    // --------------------------------------------------

    @Test
    void buildHeader_certInfoNull_shouldThrowIllegalStateException() {
        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> sut.buildHeader(null, JadesProfile.JADES_B_B, null)
        );

        assertTrue(ex.getMessage().contains("Failed to build JAdES header"));
        assertEquals("certInfo is required", ex.getCause().getMessage());
    }

    @Test
    void buildHeader_profileNull_shouldThrowIllegalStateException() {
        CertificateInfo certInfo = certificateInfo(
                List.of("CERT"),
                List.of("1.2.840.10045.4.3.2")
        );

        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> sut.buildHeader(certInfo, null, null)
        );

        assertTrue(ex.getMessage().contains("Failed to build JAdES header"));
        assertEquals("profile is required", ex.getCause().getMessage());
    }

    @Test
    void buildHeader_emptyAlgorithms_shouldThrowIllegalStateException() {
        CertificateInfo certInfo = certificateInfo(
                List.of("CERT"),
                List.of() // empty algorithms
        );

        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null)
        );

        assertTrue(ex.getCause().getMessage().contains("No signing algorithm found"));
    }

    @Test
    void buildHeader_unsupportedOid_shouldThrowIllegalStateException() {
        CertificateInfo certInfo = certificateInfo(
                List.of("CERT"),
                List.of("0.0.0.0")
        );

        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null)
        );

        assertTrue(ex.getCause().getMessage().contains("Unsupported OID"));
    }

    @Test
    void buildHeader_profileNotSupported_shouldThrowIllegalStateException() {
        CertificateInfo certInfo = certificateInfo(
                List.of("CERT"),
                List.of("1.2.840.10045.4.3.2")
        );

        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> sut.buildHeader(certInfo, JadesProfile.JADES_B_LT, null)
        );

        assertTrue(ex.getCause().getMessage().contains("not yet supported"));
    }

    // --------------------------------------------------
    // x5c ROOT TRIMMING (HAIP §6.1: issuer must not publish the self-signed root)
    // --------------------------------------------------

    @Test
    void buildHeader_trailingCertIsSelfSignedRoot_trimsItFromX5c() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();

        String rootB64 = certBase64(buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true));
        String leafB64 = certBase64(buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false));

        CertificateInfo certInfo = certificateInfo(
                List.of(leafB64, rootB64),
                List.of("1.2.840.10045.4.3.2")
        );

        JsonNode node = objectMapper.readTree(sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null));

        assertEquals(1, node.get("x5c").size());
        assertEquals(leafB64, node.get("x5c").get(0).asText());
    }

    @Test
    void buildHeader_trailingCertIsNotSelfSigned_keepsFullChain() throws Exception {
        KeyPair caKp = generateEc();
        KeyPair someOtherKp = generateEc();
        KeyPair leafKp = generateEc();

        // Trailing cert signed by a different key than its own subject — not self-signed,
        // so nothing gets trimmed (this is the "root already absent" case: everything in the
        // array is a real leaf/intermediate, none of it should be touched).
        String intermediateB64 = certBase64(buildCert(caKp, "CN=Intermediate CA", someOtherKp, "CN=Other", true));
        String leafB64 = certBase64(buildCert(leafKp, "CN=Leaf", caKp, "CN=Intermediate CA", false));

        CertificateInfo certInfo = certificateInfo(
                List.of(leafB64, intermediateB64),
                List.of("1.2.840.10045.4.3.2")
        );

        JsonNode node = objectMapper.readTree(sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null));

        assertEquals(2, node.get("x5c").size());
        assertEquals(leafB64, node.get("x5c").get(0).asText());
        assertEquals(intermediateB64, node.get("x5c").get(1).asText());
    }

    @Test
    void buildHeader_threeCertChainWithSelfSignedRoot_trimsOnlyTheRoot() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair intKp = generateEc();
        KeyPair leafKp = generateEc();

        String rootB64 = certBase64(buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true));
        String intermediateB64 = certBase64(buildCert(intKp, "CN=Intermediate CA", rootKp, "CN=Root CA", true));
        String leafB64 = certBase64(buildCert(leafKp, "CN=Leaf", intKp, "CN=Intermediate CA", false));

        CertificateInfo certInfo = certificateInfo(
                List.of(leafB64, intermediateB64, rootB64),
                List.of("1.2.840.10045.4.3.2")
        );

        JsonNode node = objectMapper.readTree(sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null));

        assertEquals(2, node.get("x5c").size());
        assertEquals(leafB64, node.get("x5c").get(0).asText());
        assertEquals(intermediateB64, node.get("x5c").get(1).asText());
    }

    @Test
    void buildHeader_unparseableTrailingCert_leavesChainUntouched() throws Exception {
        // Not valid base64/DER - isSelfSigned() must fail closed (don't trim) rather than
        // propagate the parse failure and break header building altogether.
        CertificateInfo certInfo = certificateInfo(
                List.of("not-a-real-cert", "also-not-a-real-cert"),
                List.of("1.2.840.10045.4.3.2")
        );

        JsonNode node = objectMapper.readTree(sut.buildHeader(certInfo, JadesProfile.JADES_B_B, null));

        assertEquals(2, node.get("x5c").size());
    }

    // --------------------------------------------------
    // Cert-building helpers (x5c trimming tests)
    // --------------------------------------------------

    private static KeyPair generateEc() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(256);
        return gen.generateKeyPair();
    }

    /** Builds an X.509 cert signed by {@code issuerKeyPair}; self-signed when subject == issuer key/DN. */
    private static X509Certificate buildCert(
            KeyPair subjectKeyPair, String subjectDn,
            KeyPair issuerKeyPair, String issuerDn,
            boolean isCA) throws Exception {

        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA")
                .setProvider("BC")
                .build(issuerKeyPair.getPrivate());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(System.nanoTime()),
                notBefore, notAfter,
                new X500Principal(subjectDn),
                subjectKeyPair.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private static String certBase64(X509Certificate cert) throws Exception {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }

    // --------------------------------------------------
    // Helper
    // --------------------------------------------------

    private static CertificateInfo certificateInfo(
            List<String> certificates,
            List<String> keyAlgorithms
    ) {
        return new CertificateInfo(
                certificates,
                "CN=Issuer",
                "CN=Subject",
                "123456",
                "2024-01-01",
                "2026-01-01",
                keyAlgorithms,
                256,
                false
        );
    }
}