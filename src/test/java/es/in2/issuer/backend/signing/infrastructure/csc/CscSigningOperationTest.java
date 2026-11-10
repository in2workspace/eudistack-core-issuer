package es.in2.issuer.backend.signing.infrastructure.csc;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CscSigningOperationTest {

    @Test
    void fromValue_cscValues_resolve() {
        assertThat(CscSigningOperation.fromValue("sign-hash")).isEqualTo(CscSigningOperation.SIGN_HASH);
        assertThat(CscSigningOperation.fromValue("sign-doc")).isEqualTo(CscSigningOperation.SIGN_DOC);
    }

    @Test
    void fromValue_kmsValue_isRejected_soAQtspConfigCannotReachKms() {
        assertThatThrownBy(() -> CscSigningOperation.fromValue("aws-kms"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported CSC signing type: aws-kms");
    }

    @Test
    void fromValue_unknownValue_isRejected() {
        assertThatThrownBy(() -> CscSigningOperation.fromValue("other"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
