package es.in2.issuer.backend.signing.domain.util;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SigningCertificateChecksTest {

    private final OwnKeyTestPki pki = new OwnKeyTestPki();

    @Test
    void isP256_p256Certificate_returnsTrue() {
        assertThat(SigningCertificateChecks.isP256(pki.validP256Leaf().certificate())).isTrue();
    }

    @Test
    void isP256_rsaCertificate_returnsFalse() {
        assertThat(SigningCertificateChecks.isP256(pki.rsaLeaf().certificate())).isFalse();
    }

    @Test
    void isP256_p384Certificate_returnsFalse() {
        assertThat(SigningCertificateChecks.isP256(pki.p384Leaf().certificate())).isFalse();
    }

    @Test
    void isSelfSigned_selfSignedCertificate_returnsTrue() {
        assertThat(SigningCertificateChecks.isSelfSigned(pki.selfSignedLeaf().certificate())).isTrue();
    }

    @Test
    void isSelfSigned_rootCertificate_returnsTrue() {
        assertThat(SigningCertificateChecks.isSelfSigned(pki.rootCertificate())).isTrue();
    }

    @Test
    void isSelfSigned_certificateIssuedByAnotherCa_returnsFalse() {
        assertThat(SigningCertificateChecks.isSelfSigned(pki.validP256Leaf().certificate())).isFalse();
    }

    @Test
    void isSelfSigned_sameSubjectAndIssuerButForeignSignature_returnsFalse() {
        assertThat(SigningCertificateChecks.isSelfSigned(pki.forgedSelfIssuedCertificate())).isFalse();
    }

    @Test
    void isValidAt_insideTheWindow_returnsTrue() {
        assertThat(SigningCertificateChecks.isValidAt(
                pki.expiredLeaf().certificate(), Instant.parse("2025-01-01T12:00:00Z"))).isTrue();
    }

    @Test
    void isValidAt_exactlyOnBothBounds_returnsTrue() {
        var certificate = pki.expiredLeaf().certificate();

        assertThat(SigningCertificateChecks.isValidAt(certificate, Instant.parse("2025-01-01T00:00:00Z"))).isTrue();
        assertThat(SigningCertificateChecks.isValidAt(certificate, Instant.parse("2025-01-02T00:00:00Z"))).isTrue();
    }

    @Test
    void isValidAt_justOutsideTheWindow_returnsFalse() {
        var certificate = pki.expiredLeaf().certificate();

        assertThat(SigningCertificateChecks.isValidAt(certificate, Instant.parse("2024-12-31T23:59:59Z"))).isFalse();
        assertThat(SigningCertificateChecks.isValidAt(certificate, Instant.parse("2025-01-02T00:00:01Z"))).isFalse();
    }

    @Test
    void isValidAt_expiredCertificateNow_returnsFalse() {
        assertThat(SigningCertificateChecks.isValidAt(pki.expiredLeaf().certificate(), Instant.now())).isFalse();
    }

    @Test
    void checks_nullArguments_throw() {
        var certificate = pki.validP256Leaf().certificate();

        assertThatThrownBy(() -> SigningCertificateChecks.isP256(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SigningCertificateChecks.isSelfSigned(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SigningCertificateChecks.isValidAt(null, Instant.now()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SigningCertificateChecks.isValidAt(certificate, null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
