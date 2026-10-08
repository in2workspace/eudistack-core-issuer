package es.in2.issuer.backend.signing.infrastructure.csc;

import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import java.util.List;
import java.util.stream.Stream;

import static es.in2.issuer.backend.signing.infrastructure.csc.TestCertificates.QCP_L;
import static es.in2.issuer.backend.signing.infrastructure.csc.TestCertificates.QCP_L_QSCD;
import static es.in2.issuer.backend.signing.infrastructure.csc.TestCertificates.base64Cert;
import static org.assertj.core.api.Assertions.assertThat;

class CertificateQualificationUtilsTest {

    private static final String SUBJECT = "CN=Issuer Seal,O=ACME,C=ES";

    static Stream<Arguments> certificates() {
        return Stream.of(
                Arguments.of(Named.of("QCP-l-qscd policy", List.of(base64Cert(SUBJECT, QCP_L_QSCD))), true),
                Arguments.of(Named.of("QCP-l-qscd among other policies",
                        List.of(base64Cert(SUBJECT, QCP_L, QCP_L_QSCD))), true),
                Arguments.of(Named.of("QCP-l policy only", List.of(base64Cert(SUBJECT, QCP_L))), false),
                Arguments.of(Named.of("no policy extension", List.of(base64Cert(SUBJECT))), false),
                Arguments.of(Named.of("not base64", List.of("%%%not-base64%%%")), false),
                Arguments.of(Named.of("base64 but not a certificate", List.of("aGVsbG8=")), false));
    }

    @ParameterizedTest
    @MethodSource("certificates")
    void isQualifiedSeal_detectsQualificationFromLeafPolicy(List<String> chain, boolean expected) {
        // Act
        boolean qualified = CertificateQualificationUtils.isQualifiedSeal(chain);

        // Assert
        assertThat(qualified).isEqualTo(expected);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void isQualifiedSeal_withoutCertificates_returnsFalse(List<String> chain) {
        assertThat(CertificateQualificationUtils.isQualifiedSeal(chain)).isFalse();
    }
}
