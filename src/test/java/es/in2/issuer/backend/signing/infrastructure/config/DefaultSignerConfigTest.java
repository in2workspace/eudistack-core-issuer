package es.in2.issuer.backend.signing.infrastructure.config;

import org.junit.jupiter.api.Test;

import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

class DefaultSignerConfigTest {

    private String getTestCertPath(String filename) {
        return Objects.requireNonNull(
                getClass().getClassLoader().getResource("certs/" + filename),
                "Test certificate not found: " + filename
        ).getPath();
    }

    @Test
    void shouldExtractFieldsFromCertificate() {
        DefaultSignerConfig config = new DefaultSignerConfig(getTestCertPath("test-eseal.crt"));

        assertEquals("VATES-A15456585", config.getOrganizationIdentifier());
        assertEquals("ALTIA CONSULTORES, SA", config.getOrganization());
        assertEquals("ES", config.getCountry());
        assertEquals("ALTIA CONSULTORES, SA - Sello Electronico", config.getCommonName());
        assertEquals("A15456585", config.getSerialNumber());
    }

    @Test
    void shouldThrowWhenCertPathIsBlank() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new DefaultSignerConfig(""));
        assertTrue(ex.getMessage().contains("signing.certificate.cert-path is required"));
    }

    @Test
    void shouldThrowWhenCertPathIsNull() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new DefaultSignerConfig(null));
        assertTrue(ex.getMessage().contains("signing.certificate.cert-path is required"));
    }

    @Test
    void shouldThrowWhenCertificateFileDoesNotExist() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new DefaultSignerConfig("/nonexistent/path/cert.crt"));
        assertTrue(ex.getMessage().contains("Failed to read signer identity from certificate"));
    }

    @Test
    void shouldThrowWhenCertificateMissingOrganizationIdentifier() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new DefaultSignerConfig(getTestCertPath("test-no-orgid.crt")));
        assertTrue(ex.getMessage().contains("does not contain organizationIdentifier"));
    }
}
