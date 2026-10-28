package es.in2.issuer.backend.signing.domain.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningProviderTypeTest {

    @Test
    void fromCscOperation_cscValues_resolve() {
        assertThat(SigningProviderType.fromCscOperation("sign-hash")).isEqualTo(SigningProviderType.CSC_SIGN_HASH);
        assertThat(SigningProviderType.fromCscOperation("sign-doc")).isEqualTo(SigningProviderType.CSC_SIGN_DOC);
    }

    @Test
    void fromCscOperation_kmsValue_isRejected_soAQtspConfigCannotReachKms() {
        assertThatThrownBy(() -> SigningProviderType.fromCscOperation("aws-kms"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported CSC signing type: aws-kms");
    }

    @Test
    void fromCscOperation_unknownValue_isRejected() {
        assertThatThrownBy(() -> SigningProviderType.fromCscOperation("other"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
