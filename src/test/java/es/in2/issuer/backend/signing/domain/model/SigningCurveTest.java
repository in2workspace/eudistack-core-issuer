package es.in2.issuer.backend.signing.domain.model;

import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningCurveTest {

    private final OwnKeyTestPki pki = new OwnKeyTestPki();

    @Test
    void of_p256Certificate_isP256() {
        assertThat(SigningCurve.of(pki.validP256Leaf().certificate())).contains(SigningCurve.P_256);
    }

    @Test
    void of_p384Certificate_isEmpty() {
        assertThat(SigningCurve.of(pki.p384Leaf().certificate())).isEmpty();
    }

    @Test
    void of_anotherCurveOf256Bits_isEmpty() {
        assertThat(SigningCurve.of(pki.brainpoolP256Leaf().certificate())).isEmpty();
    }

    @Test
    void of_rsaCertificate_isEmpty() {
        assertThat(SigningCurve.of(pki.rsaLeaf().certificate())).isEmpty();
    }

    @Test
    void of_nullCertificate_isRejected() {
        assertThatThrownBy(() -> SigningCurve.of(null)).isInstanceOf(IllegalArgumentException.class);
    }
}
