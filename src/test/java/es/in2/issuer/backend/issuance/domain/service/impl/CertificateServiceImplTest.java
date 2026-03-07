package es.in2.issuer.backend.issuance.domain.service.impl;

import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class CertificateServiceImplTest {

    @Mock
    private AccessTokenService accessTokenService;

    private CertificateServiceImpl certificateService;

    // Self-signed certificate WITH OID 2.5.4.97 = "VATES-B12345678"
    // Generated with: keytool -genkeypair -dname "CN=Test Certificate, O=Test Org, OID.2.5.4.97=VATES-B12345678"
    private static final String PEM_CERT_WITH_ORG_ID =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDNDCCAhygAwIBAgIJALPOqznIx7nCMA0GCSqGSIb3DQEBDAUAMEgxGDAWBgNV" +
            "BGETD1ZBVEVTLUIxMjM0NTY3ODERMA8GA1UEChMIVGVzdCBPcmcxGTAXBgNVBAMT" +
            "EFRlc3QgQ2VydGlmaWNhdGUwHhcNMjYwMzAxMDkzNzU0WhcNMzYwMjI3MDkzNzU0" +
            "WjBIMRgwFgYDVQRhEw9WQVRFUy1CMTIzNDU2NzgxETAPBgNVBAoTCFRlc3QgT3Jn" +
            "MRkwFwYDVQQDExBUZXN0IENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOC" +
            "AQ8AMIIBCgKCAQEAt0J5ykwWZ2num98FypfA9T69bTl+ehpJ+GUGT+CbZKn5qrfR" +
            "92UMDWD5zT7YYiaCeURLSQ+byV0UkhrnPlakkto5gyA26bzjHV1UICwKKR8tcspd" +
            "m8nJVC7e3AahLDdQnPxg4Nd3mCoeenaAOOA68d03nue0toTQYtt9vbfljaESGLdF" +
            "Jk4CORpIx1JF+sRXmrSoVKumAWajpE74EJuYVen2MfoYwtNw/vXX1Vl+mT96k1zu" +
            "BxdAl5N7BLi9Wl2JP9Fo7a3Jv+arTESChYS/HOKFUvYtVne5wZzTFoqw5BLdVH2y" +
            "MH2J879dJEXtBHlykVetqi782S433C9ui/R8MwIDAQABoyEwHzAdBgNVHQ4EFgQU" +
            "ZnqlxVaJs43707A51W1OPBF8CrkwDQYJKoZIhvcNAQEMBQADggEBAKmEeRpqWO3l" +
            "QKy/yfVe0r6Es01WUSgFI/gBODzHpHbDlN+0AbaP7HsiyLnP6xXlNcmCJRt7XjcX" +
            "zRYYIVPV270W7kyELwAUAb7Lh2W2UtTwyyhG0ksPk4zBpDA81QwegujEAdygK5BI" +
            "6xfGla6Ks6Cx103p5WfatCbyXWLmwacIYnfXFObYX4WeHh3+SH3TOht3qBi4F6Ut" +
            "o1PQ07RpAwZ9YgSpUW9P0tmiNSlM/l1OuRJT+iHHVbXKwmEkxHw5pDng2nH/fb29" +
            "jVI9oa2C4wBgxZnimb1c0HvOZGBLmmL/8x/UDZB4UHMsDvsXonCpEgUVctqd97zQ" +
            "r74MMoLFyck=\n" +
            "-----END CERTIFICATE-----";

    // Self-signed certificate WITHOUT OID 2.5.4.97
    // Generated with: keytool -genkeypair -dname "CN=Test Certificate No OrgId, O=Test Org"
    private static final String PEM_CERT_WITHOUT_ORG_ID =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDETCCAfmgAwIBAgIIAbZpVtAOQhUwDQYJKoZIhvcNAQEMBQAwNzERMA8GA1UE" +
            "ChMIVGVzdCBPcmcxIjAgBgNVBAMTGVRlc3QgQ2VydGlmaWNhdGUgTm8gT3JnSWQw" +
            "HhcNMjYwMzAxMDkzODAyWhcNMzYwMjI3MDkzODAyWjA3MREwDwYDVQQKEwhUZXN0" +
            "IE9yZzEiMCAGA1UEAxMZVGVzdCBDZXJ0aWZpY2F0ZSBObyBPcmdJZDCCASIwDQYJ" +
            "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMS2PRWa2xgokQDiqC5gOfSmVDw5mMQw" +
            "aRvrFhmlk4/a2afOHtq2aUxoJa2rvLmH6uO4uXUWSzqonJE4s6IGunxYkzrqBbHo" +
            "1YvOYVVVc0E2S9PJ7AQp2z7ZNL1Q+6W4jLGhXqlUt+kuXwzlT8LcTyAqYNY6hnTy" +
            "OfYzQ3S//aKjw7tiKGpFxLC0txNBhHEMUwAc9RvmnxqHq+0yKytxIU5G40vJOeB5" +
            "ssF/FoyveosCk3LEKil4CPPYl1B5mIAW8AtGrCIh4jNV3YHh87LEF6wNj3tonEPl" +
            "FuiB1jKKmzcx1WP8eA7AiB88VLvccBvC2a4mzPYWIUQK3Ma+s+PfD5ECAwEAAaMh" +
            "MB8wHQYDVR0OBBYEFLhiXHEGd3gCbYPspyrJeO0hlYp4MA0GCSqGSIb3DQEBDAUA" +
            "A4IBAQBqulS9GEhAPIdLmnT16m6n11wjeGRIJx2RsGryAFpx80Mf4CU3I7xeW+QG" +
            "8ZitZL1KybMotRBzyCLjr5MxYqAEBfWJuG9Nv8h1pnGVb2I4iU7vJxjochGP++Wq" +
            "b7ERcgbiBhg+HQyO8hYjUDc1zIpTD58agHPNIHNsm20tyowJQuwLdcTTTkgWdzMq" +
            "vsCVR5m7ntmYN+VkDIbZv/brR9R8usqNrYEUwGREhx0DeYxgPMhfU6TvO0Aa27EU" +
            "GcFockstwkpCB26DHJMlciIG2QOlCGJloePhhNUsLRK5rbUDsNxoVqBdbufVVdXu" +
            "6iAt2vBZruSnz1lUvaezIo6B5vTF\n" +
            "-----END CERTIFICATE-----";

    @BeforeEach
    void setUp() {
        certificateService = new CertificateServiceImpl(accessTokenService);
    }

    // ── Helper: strip PEM headers to get raw Base64 ─────────────────────

    private static String stripPemHeaders(String pem) {
        return pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
    }

    // ── extractClientCertificate tests ──────────────────────────────────

    @Test
    @DisplayName("extractClientCertificate - valid PEM certificate - returns X509Certificate")
    void extractClientCertificate_validPem_returnsX509Certificate() {
        StepVerifier.create(certificateService.extractClientCertificate(PEM_CERT_WITH_ORG_ID))
                .assertNext(result -> {
                    assertNotNull(result);
                    assertInstanceOf(X509Certificate.class, result);
                    assertTrue(result.getSubjectX500Principal().getName().contains("Test Certificate"));
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("extractClientCertificate - valid Base64 without PEM headers - returns X509Certificate")
    void extractClientCertificate_validBase64NoPemHeaders_returnsX509Certificate() {
        String base64Only = stripPemHeaders(PEM_CERT_WITH_ORG_ID);

        StepVerifier.create(certificateService.extractClientCertificate(base64Only))
                .assertNext(result -> {
                    assertNotNull(result);
                    assertInstanceOf(X509Certificate.class, result);
                    assertTrue(result.getSubjectX500Principal().getName().contains("Test Certificate"));
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("extractClientCertificate - invalid Base64 string - returns Mono.error")
    void extractClientCertificate_invalidBase64_returnsMonoError() {
        String invalidCert = "this-is-not-valid-base64-!!!@@@";

        StepVerifier.create(certificateService.extractClientCertificate(invalidCert))
                .expectErrorSatisfies(error -> {
                    assertInstanceOf(RuntimeException.class, error);
                    assertEquals("Invalid certificate format", error.getMessage());
                })
                .verify();
    }

    @Test
    @DisplayName("extractClientCertificate - null input - returns empty Mono")
    void extractClientCertificate_nullInput_returnsEmptyMono() {
        StepVerifier.create(certificateService.extractClientCertificate(null))
                .verifyComplete();
    }

    @Test
    @DisplayName("extractClientCertificate - empty string - returns Mono.error")
    void extractClientCertificate_emptyString_returnsMonoError() {
        StepVerifier.create(certificateService.extractClientCertificate(""))
                .expectErrorSatisfies(error -> {
                    assertInstanceOf(RuntimeException.class, error);
                    assertEquals("Invalid certificate format", error.getMessage());
                })
                .verify();
    }

    @Test
    @DisplayName("extractClientCertificate - valid Base64 but not a certificate - returns Mono.error")
    void extractClientCertificate_validBase64ButNotCert_returnsMonoError() {
        String notACert = Base64.getEncoder().encodeToString("this is not a certificate".getBytes());

        StepVerifier.create(certificateService.extractClientCertificate(notACert))
                .expectErrorSatisfies(error -> {
                    assertInstanceOf(RuntimeException.class, error);
                    assertEquals("Invalid certificate format", error.getMessage());
                })
                .verify();
    }

    // ── getOrganizationIdFromCertificate tests ──────────────────────────

    @Test
    @DisplayName("getOrganizationIdFromCertificate - certificate with OID 2.5.4.97 - returns organization ID")
    void getOrganizationIdFromCertificate_withOid_returnsOrganizationId() {
        StepVerifier.create(certificateService.getOrganizationIdFromCertificate(PEM_CERT_WITH_ORG_ID))
                .assertNext(orgId -> assertEquals("VATES-B12345678", orgId))
                .verifyComplete();
    }

    @Test
    @DisplayName("getOrganizationIdFromCertificate - certificate without OID 2.5.4.97 - returns Mono.error")
    void getOrganizationIdFromCertificate_withoutOid_returnsMonoError() {
        StepVerifier.create(certificateService.getOrganizationIdFromCertificate(PEM_CERT_WITHOUT_ORG_ID))
                .expectErrorSatisfies(error -> {
                    assertInstanceOf(RuntimeException.class, error);
                    assertTrue(error.getMessage().contains("Organization ID not found"));
                })
                .verify();
    }

    @Test
    @DisplayName("getOrganizationIdFromCertificate - null certificate - returns empty Mono")
    void getOrganizationIdFromCertificate_nullCert_returnsEmptyMono() {
        StepVerifier.create(certificateService.getOrganizationIdFromCertificate(null))
                .verifyComplete();
    }

    @Test
    @DisplayName("getOrganizationIdFromCertificate - Base64 certificate with OID - returns organization ID")
    void getOrganizationIdFromCertificate_base64WithOid_returnsOrganizationId() {
        String base64Only = stripPemHeaders(PEM_CERT_WITH_ORG_ID);

        StepVerifier.create(certificateService.getOrganizationIdFromCertificate(base64Only))
                .assertNext(orgId -> assertEquals("VATES-B12345678", orgId))
                .verifyComplete();
    }
}
