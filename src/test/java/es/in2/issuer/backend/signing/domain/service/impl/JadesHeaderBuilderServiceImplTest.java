package es.in2.issuer.backend.signing.domain.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JadesHeaderBuilderServiceImplTest {

    private ObjectMapper objectMapper;
    private JadesHeaderBuilderServiceImpl sut;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        sut = new JadesHeaderBuilderServiceImpl(objectMapper);
    }


    // The STG signing chain, as the QTSP returns it from credentials/info: an EC leaf issued by
    // a self-signed test root. Both are test certificates already served publicly inside the
    // Status List Token's x5c header.
    private static final String LEAF_CERT =
            "MIIDRzCCAu2gAwIBAgIUTCNdye+Ht3Dt8901YH9xVWhjIUYwCgYIKoZIzj0EAwIweDELMAkG"
                    + "A1UEBhMCRVMxHjAcBgNVBAoMFUFMVElBIENPTlNVTFRPUkVTLCBTQTEYMBYGA1UEYQwPVkFU"
                    + "RVMtQTE1NDU2NTg1MS8wLQYDVQQDDCZBTFRJQSBDT05TVUxUT1JFUywgU0EgLSBSb290IENB"
                    + "ICh0ZXN0KTAeFw0yNjA4MjcxMjM2MDZaFw0yODA4MjYxMjM2MDZaMIGPMQswCQYDVQQGEwJF"
                    + "UzEeMBwGA1UECgwVQUxUSUEgQ09OU1VMVE9SRVMsIFNBMRgwFgYDVQRhDA9WQVRFUy1BMTU0"
                    + "NTY1ODUxMjAwBgNVBAMMKUFMVElBIENPTlNVTFRPUkVTLCBTQSAtIFNlbGxvIEVsZWN0cm9u"
                    + "aWNvMRIwEAYDVQQFEwlBMTU0NTY1ODUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQn8PHv"
                    + "UJJceAPjpok3ibwcOmclGqDhdl6vMUjk4KxBFYQCwEqNKyzoHUhcF5WJz7NRRY3eRGe/NDFS"
                    + "xngfI/rLo4IBOzCCATcwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBsAwQAYDVR0gBDkw"
                    + "NzA1BgcEAIvsQAECMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmV4YW1wbGUuY29tL2Nw"
                    + "cy8wHQYDVR0OBBYEFEjsUg2nJLrwATlWzMpCj1MnDn0CMIG1BgNVHSMEga0wgaqAFNA923Ch"
                    + "kacDwN7C7+zLgpCv83PAoXykejB4MQswCQYDVQQGEwJFUzEeMBwGA1UECgwVQUxUSUEgQ09O"
                    + "U1VMVE9SRVMsIFNBMRgwFgYDVQRhDA9WQVRFUy1BMTU0NTY1ODUxLzAtBgNVBAMMJkFMVElB"
                    + "IENPTlNVTFRPUkVTLCBTQSAtIFJvb3QgQ0EgKHRlc3QpghQJp2849suVhdCZ6jigC1oKDmgw"
                    + "jjAKBggqhkjOPQQDAgNIADBFAiEA1wH+FI8XIS2K5uaXLyOU9sAtDNVh5yVOQo/h6UelT68C"
                    + "IA0a2uXGqoCcu1h2AwuK9NSY4VQs2btLiaYcZsI9J/Sg";

    private static final String ROOT_CERT =
            "MIIC8TCCApegAwIBAgIUCadvOPbLlYXQmeo4oAtaCg5oMI4wCgYIKoZIzj0EAwIweDELMAkG"
                    + "A1UEBhMCRVMxHjAcBgNVBAoMFUFMVElBIENPTlNVTFRPUkVTLCBTQTEYMBYGA1UEYQwPVkFU"
                    + "RVMtQTE1NDU2NTg1MS8wLQYDVQQDDCZBTFRJQSBDT05TVUxUT1JFUywgU0EgLSBSb290IENB"
                    + "ICh0ZXN0KTAeFw0yNjA4MjcxMjM2MDZaFw0zMTA4MjYxMjM2MDZaMHgxCzAJBgNVBAYTAkVT"
                    + "MR4wHAYDVQQKDBVBTFRJQSBDT05TVUxUT1JFUywgU0ExGDAWBgNVBGEMD1ZBVEVTLUExNTQ1"
                    + "NjU4NTEvMC0GA1UEAwwmQUxUSUEgQ09OU1VMVE9SRVMsIFNBIC0gUm9vdCBDQSAodGVzdCkw"
                    + "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATxlwn5jbOwyeKobRTVGNGBO8/uHigCz+AS8M4A"
                    + "fgLz+EwDy1AD1p4ZaOg3zx2L0MvRfD9FRI5XSTOvwuMhgV8do4H+MIH7MBIGA1UdEwEB/wQI"
                    + "MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTQPdtwoZGnA8Dewu/sy4KQr/Nz"
                    + "wDCBtQYDVR0jBIGtMIGqgBTQPdtwoZGnA8Dewu/sy4KQr/NzwKF8pHoweDELMAkGA1UEBhMC"
                    + "RVMxHjAcBgNVBAoMFUFMVElBIENPTlNVTFRPUkVTLCBTQTEYMBYGA1UEYQwPVkFURVMtQTE1"
                    + "NDU2NTg1MS8wLQYDVQQDDCZBTFRJQSBDT05TVUxUT1JFUywgU0EgLSBSb290IENBICh0ZXN0"
                    + "KYIUCadvOPbLlYXQmeo4oAtaCg5oMI4wCgYIKoZIzj0EAwIDSAAwRQIgBigx4MIpZfE8lnh+"
                    + "945rs2RS83MCEAMb6KrN2f/iQOsCIQCU4qVtnbF7rFwngezJaeYm7reqA3Y19tlyv0FtgN6F"
                    + "Xw==";

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
    // HAIP 6.1 / 6.1.1 — trust anchor must not travel in x5c
    // --------------------------------------------------

    @Test
    void buildHeader_chainEndingInSelfSignedRoot_dropsTheRootFromX5c() throws Exception {
        CertificateInfo certInfo = certificateInfo(
                List.of(LEAF_CERT, ROOT_CERT),
                List.of("1.2.840.10045.4.3.2")
        );

        JsonNode node = objectMapper.readTree(sut.buildHeader(certInfo, JadesProfile.JADES_B_T, "statuslist+jwt"));

        JsonNode x5c = node.get("x5c");
        assertEquals(1, x5c.size(), "the self-signed anchor must not be included");
        assertEquals(LEAF_CERT, x5c.get(0).asText());
    }

    @Test
    void buildHeader_leafOnlyChain_isLeftUntouched() throws Exception {
        CertificateInfo certInfo = certificateInfo(
                List.of(LEAF_CERT),
                List.of("1.2.840.10045.4.3.2")
        );

        JsonNode node = objectMapper.readTree(sut.buildHeader(certInfo, JadesProfile.JADES_B_T, null));

        assertEquals(1, node.get("x5c").size());
        assertEquals(LEAF_CERT, node.get("x5c").get(0).asText());
    }

    @Test
    void buildHeader_selfSignedLeafAlone_isKeptRatherThanEmptyingX5c() throws Exception {
        // HAIP forbids a self-signed signing certificate, but an empty x5c would hide the
        // misconfiguration behind an unverifiable signature instead of surfacing it.
        CertificateInfo certInfo = certificateInfo(
                List.of(ROOT_CERT),
                List.of("1.2.840.10045.4.3.2")
        );

        JsonNode node = objectMapper.readTree(sut.buildHeader(certInfo, JadesProfile.JADES_B_T, null));

        assertEquals(1, node.get("x5c").size());
        assertEquals(ROOT_CERT, node.get("x5c").get(0).asText());
    }

    @Test
    void buildHeader_unparseableChainEntries_areKept() throws Exception {
        // Placeholder values must not be mistaken for anchors and silently dropped.
        CertificateInfo certInfo = certificateInfo(
                List.of("MIIC...", "MIID..."),
                List.of("1.2.840.10045.4.3.2")
        );

        JsonNode node = objectMapper.readTree(sut.buildHeader(certInfo, JadesProfile.JADES_B_T, null));

        assertEquals(2, node.get("x5c").size());
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