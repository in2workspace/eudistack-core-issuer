package es.in2.issuer.backend.signing.infrastructure.csc.v2.mapper;

import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static es.in2.issuer.backend.signing.infrastructure.csc.TestCertificates.QCP_L_QSCD;
import static es.in2.issuer.backend.signing.infrastructure.csc.TestCertificates.base64Cert;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CscV2CertificateInfoMapperTest {

    private final CscV2CertificateInfoMapper mapper = new CscV2CertificateInfoMapper();

    @Test
    void map_withValidResponse_mapsAllFields() {
        // Arrange
        Map<String, Object> response = response();

        // Act
        CertificateInfo info = mapper.map(response);

        // Assert
        assertThat(info.subjectDN()).isEqualTo("CN=Issuer Seal");
        assertThat(info.issuerDN()).isEqualTo("CN=Root CA");
        assertThat(info.serialNumber()).isEqualTo("0A1B2C");
        assertThat(info.validFrom()).isEqualTo("20250101000000Z");
        assertThat(info.validTo()).isEqualTo("20300101000000Z");
        assertThat(info.keyAlgorithms()).containsExactly("1.2.840.10045.4.3.2");
        assertThat(info.keyLength()).isEqualTo(256);
        assertThat(info.qualifiedSeal()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"enabled", "VALID"})
    void map_withEnabledKeyStatus_succeeds(String status) {
        Map<String, Object> response = response();
        key(response).put("status", status);

        assertThat(mapper.map(response).certificates()).hasSize(1);
    }

    @Test
    void map_whenResponseNull_throws() {
        assertThatThrownBy(() -> mapper.map(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("CSC credentials/info response is null");
    }

    static Stream<Arguments> invalidResponses() {
        return Stream.of(
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("missing key",
                        r -> r.remove("key")), "Missing 'key' section in CSC response"),
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("disabled key",
                        r -> key(r).put("status", "disabled")), "Signing key is not enabled: disabled"),
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("missing algo",
                        r -> key(r).remove("algo")), "Missing 'key.algo' in CSC response"),
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("empty algo",
                        r -> key(r).put("algo", List.of())), "No signing algorithm returned by QTSP"),
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("missing cert",
                        r -> r.remove("cert")), "Missing 'cert' section in CSC response"),
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("revoked cert",
                        r -> cert(r).put("status", "revoked")), "Certificate is not valid: revoked"),
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("missing cert status",
                        r -> cert(r).remove("status")), "Certificate is not valid: null"),
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("missing chain",
                        r -> cert(r).remove("certificates")), "Missing 'cert.certificates' in CSC response"),
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("empty chain",
                        r -> cert(r).put("certificates", List.of())), "No certificate chain returned by QTSP"));
    }

    @ParameterizedTest
    @MethodSource("invalidResponses")
    void map_withInvalidResponse_throws(Consumer<Map<String, Object>> mutation, String expectedMessage) {
        // Arrange
        Map<String, Object> response = response();
        mutation.accept(response);

        // Act + Assert
        assertThatThrownBy(() -> mapper.map(response))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage(expectedMessage);
    }

    private static Map<String, Object> response() {
        Map<String, Object> key = new HashMap<>();
        key.put("status", "enabled");
        key.put("algo", List.of("1.2.840.10045.4.3.2"));
        key.put("len", 256);

        Map<String, Object> cert = new HashMap<>();
        cert.put("status", "valid");
        cert.put("certificates", List.of(base64Cert("CN=Issuer Seal,O=ACME,C=ES", QCP_L_QSCD)));
        cert.put("subjectDN", "CN=Issuer Seal");
        cert.put("issuerDN", "CN=Root CA");
        cert.put("serialNumber", "0A1B2C");
        cert.put("validFrom", "20250101000000Z");
        cert.put("validTo", "20300101000000Z");

        Map<String, Object> response = new HashMap<>();
        response.put("key", key);
        response.put("cert", cert);
        return response;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> key(Map<String, Object> response) {
        return (Map<String, Object>) response.get("key");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cert(Map<String, Object> response) {
        return (Map<String, Object>) response.get("cert");
    }
}
