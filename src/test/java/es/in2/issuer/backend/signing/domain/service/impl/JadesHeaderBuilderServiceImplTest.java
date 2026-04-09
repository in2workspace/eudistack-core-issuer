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
                256
        );
    }
}