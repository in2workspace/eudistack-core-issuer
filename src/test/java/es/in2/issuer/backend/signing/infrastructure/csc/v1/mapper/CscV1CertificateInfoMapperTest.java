package es.in2.issuer.backend.signing.infrastructure.csc.v1.mapper;

import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("CscV1CertificateInfoMapper — maps CSC credentials/info response")
class CscV1CertificateInfoMapperTest {

    private final CscV1CertificateInfoMapper mapper = new CscV1CertificateInfoMapper();

    @Test
    @DisplayName("map — when response is null — throws IllegalStateException")
    void map_nullResponse_throwsIllegalStateException() {
        assertThatThrownBy(() -> mapper.map(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("response is null");
    }

    @Test
    @DisplayName("map — when 'key' section missing — throws IllegalStateException")
    void map_missingKeySection_throwsIllegalStateException() {
        Map<String, Object> response = new HashMap<>();
        response.put("cert", buildCert("valid", List.of("cert1"), "dn", "sdn", "sn", "from", "to"));

        assertThatThrownBy(() -> mapper.map(response))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("'key'");
    }

    @Test
    @DisplayName("map — when 'cert' section missing — throws IllegalStateException")
    void map_missingCertSection_throwsIllegalStateException() {
        Map<String, Object> response = new HashMap<>();
        response.put("key", buildKey("enabled", List.of("1.2.840.10045.4.3.2"), 256));

        assertThatThrownBy(() -> mapper.map(response))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("'cert'");
    }

    @Test
    @DisplayName("map — when key.status is not 'enabled' — throws IllegalStateException")
    void map_keyStatusDisabled_throwsIllegalStateException() {
        Map<String, Object> response = buildFullResponse("disabled", "valid");

        assertThatThrownBy(() -> mapper.map(response))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not enabled");
    }

    @Test
    @DisplayName("map — when key.algo is empty — throws IllegalStateException")
    void map_emptyKeyAlgo_throwsIllegalStateException() {
        Map<String, Object> response = buildFullResponse("enabled", "valid");
        ((Map<String, Object>) response.get("key")).put("algo", List.of());

        assertThatThrownBy(() -> mapper.map(response))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No signing algorithm");
    }

    @Test
    @DisplayName("map — when cert.status is not 'valid' — throws IllegalStateException")
    void map_certStatusExpired_throwsIllegalStateException() {
        Map<String, Object> response = buildFullResponse("enabled", "expired");

        assertThatThrownBy(() -> mapper.map(response))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not valid");
    }

    @Test
    @DisplayName("map — when cert.certificates is empty — throws IllegalStateException")
    void map_emptyCertificates_throwsIllegalStateException() {
        Map<String, Object> response = buildFullResponse("enabled", "valid");
        ((Map<String, Object>) response.get("cert")).put("certificates", List.of());

        assertThatThrownBy(() -> mapper.map(response))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No certificate chain");
    }

    @Test
    @DisplayName("map — valid response — returns populated CertificateInfo")
    void map_validResponse_returnsPopulatedCertificateInfo() {
        Map<String, Object> response = buildFullResponse("enabled", "valid");

        CertificateInfo info = mapper.map(response);

        assertThat(info.certificates()).containsExactly("cert-pem");
        assertThat(info.issuerDN()).isEqualTo("issuerDN");
        assertThat(info.subjectDN()).isEqualTo("subjectDN");
        assertThat(info.serialNumber()).isEqualTo("serialNumber");
        assertThat(info.validFrom()).isEqualTo("2024-01-01");
        assertThat(info.validTo()).isEqualTo("2026-01-01");
        assertThat(info.keyAlgorithms()).containsExactly("1.2.840.10045.4.3.2");
        assertThat(info.keyLength()).isEqualTo(256);
    }


    private Map<String, Object> buildFullResponse(String keyStatus, String certStatus) {
        Map<String, Object> response = new HashMap<>();
        response.put("key", buildKey(keyStatus, List.of("1.2.840.10045.4.3.2"), 256));
        response.put("cert", buildCert(certStatus, List.of("cert-pem"),
                "issuerDN", "subjectDN", "serialNumber", "2024-01-01", "2026-01-01"));
        return response;
    }

    private Map<String, Object> buildKey(String status, List<String> algos, Integer len) {
        Map<String, Object> key = new HashMap<>();
        key.put("status", status);
        key.put("algo", algos);
        key.put("len", len);
        return key;
    }

    private Map<String, Object> buildCert(String status, List<String> certs,
                                           String issuerDN, String subjectDN,
                                           String serialNumber, String validFrom, String validTo) {
        Map<String, Object> cert = new HashMap<>();
        cert.put("status", status);
        cert.put("certificates", certs);
        cert.put("issuerDN", issuerDN);
        cert.put("subjectDN", subjectDN);
        cert.put("serialNumber", serialNumber);
        cert.put("validFrom", validFrom);
        cert.put("validTo", validTo);
        return cert;
    }
}

