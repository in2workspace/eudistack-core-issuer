package es.in2.issuer.backend.signing.infrastructure.csc.v1.mapper;

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

class CscV1CertificateInfoMapperTest {

    private static final String SUBJECT = "CN=Issuer Seal,O=ACME,C=ES";

    private final CscV1CertificateInfoMapper mapper = new CscV1CertificateInfoMapper();

    @Test
    void map_withExplicitCertMetadata_usesResponseValues() {
        // Arrange
        Map<String, Object> response = response(QCP_L_QSCD);
        cert(response).put("subjectDN", "CN=From Response");
        cert(response).put("issuerDN", "CN=Response CA");
        cert(response).put("serialNumber", "ABC");

        // Act
        CertificateInfo info = mapper.map(response);

        // Assert
        assertThat(info.subjectDN()).isEqualTo("CN=From Response");
        assertThat(info.issuerDN()).isEqualTo("CN=Response CA");
        assertThat(info.serialNumber()).isEqualTo("ABC");
        assertThat(info.keyAlgorithms()).containsExactly("1.2.840.10045.4.3.2");
        assertThat(info.keyLength()).isEqualTo(256);
        assertThat(info.validFrom()).isEqualTo("20250101000000Z");
        assertThat(info.qualifiedSeal()).isTrue();
    }

    @Test
    void map_withoutSubjectDn_extractsMetadataFromLeafCertificate() {
        // Arrange
        Map<String, Object> response = response();

        // Act
        CertificateInfo info = mapper.map(response);

        // Assert
        assertThat(info.subjectDN()).contains("CN=Issuer Seal");
        assertThat(info.issuerDN()).contains("CN=Issuer Seal");
        assertThat(info.serialNumber()).isEqualTo("A1B2C");
        assertThat(info.qualifiedSeal()).isFalse();
    }

    @Test
    void map_withoutSubjectDnAndUnparseableCertificate_keepsNullMetadata() {
        // Arrange
        Map<String, Object> response = response();
        cert(response).put("certificates", List.of("aGVsbG8="));

        // Act
        CertificateInfo info = mapper.map(response);

        // Assert
        assertThat(info.subjectDN()).isNull();
        assertThat(info.certificates()).containsExactly("aGVsbG8=");
    }

    @ParameterizedTest
    @ValueSource(strings = {"enabled", "VALID", "Enabled"})
    void map_withEnabledKeyStatus_succeeds(String status) {
        Map<String, Object> response = response();
        key(response).put("status", status);

        assertThat(mapper.map(response).certificates()).hasSize(1);
    }

    @Test
    void map_withoutKeyOrCertStatus_succeeds() {
        Map<String, Object> response = response();
        key(response).remove("status");
        cert(response).remove("status");

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
                Arguments.of(Named.<Consumer<Map<String, Object>>>of("expired cert",
                        r -> cert(r).put("status", "expired")), "Certificate is not valid: expired"),
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

    private static Map<String, Object> response(String... policyOids) {
        Map<String, Object> key = new HashMap<>();
        key.put("status", "enabled");
        key.put("algo", List.of("1.2.840.10045.4.3.2"));
        key.put("len", 256);

        Map<String, Object> cert = new HashMap<>();
        cert.put("status", "valid");
        cert.put("certificates", List.of(base64Cert(SUBJECT, policyOids)));
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
