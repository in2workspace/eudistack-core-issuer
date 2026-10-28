package es.in2.issuer.backend.signing.domain.util;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

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
        Instant now = Instant.now();

        assertThatThrownBy(() -> SigningCertificateChecks.isP256(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SigningCertificateChecks.isSelfSigned(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SigningCertificateChecks.isValidAt(null, now))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SigningCertificateChecks.isValidAt(certificate, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");

    @Test
    void isEndEntity_leafWithoutOrWithCaFalse_returnsTrue() {
        assertThat(SigningCertificateChecks.isEndEntity(pki.validP256Leaf().certificate())).isTrue();
        assertThat(SigningCertificateChecks.isEndEntity(pki.signingLeafWithExtensions().certificate())).isTrue();
    }

    @Test
    void isEndEntity_caCertificate_returnsFalse() {
        assertThat(SigningCertificateChecks.isEndEntity(pki.caLeaf().certificate())).isFalse();
        assertThat(SigningCertificateChecks.isEndEntity(pki.rootCertificate())).isFalse();
    }

    @Test
    void allowsSigning_signingKeyUsageOrNone_returnsTrue() {
        assertThat(SigningCertificateChecks.allowsSigning(pki.signingLeafWithExtensions().certificate())).isTrue();
        assertThat(SigningCertificateChecks.allowsSigning(pki.validP256Leaf().certificate())).isTrue();
    }

    @Test
    void allowsSigning_certSignOnly_returnsFalse() {
        assertThat(SigningCertificateChecks.allowsSigning(pki.certSignOnlyLeaf().certificate())).isFalse();
    }

    @Test
    void isLinkedChain_singleLeaf_returnsTrue() {
        assertThat(SigningCertificateChecks.isLinkedChain(List.of(pki.validP256Leaf().certificate()), NOW)).isTrue();
    }

    @Test
    void isLinkedChain_leafAndItsIntermediate_returnsTrue() {
        assertThat(SigningCertificateChecks.isLinkedChain(pki.chainWithIntermediate().certificates(), NOW)).isTrue();
    }

    @Test
    void isLinkedChain_leafAndRoot_returnsTrue() {
        assertThat(SigningCertificateChecks.isLinkedChain(
                List.of(pki.validP256Leaf().certificate(), pki.rootCertificate()), NOW)).isTrue();
    }

    @Test
    void isLinkedChain_expiredIntermediate_returnsFalse() {
        assertThat(SigningCertificateChecks.isLinkedChain(pki.chainWithExpiredIntermediate().certificates(), NOW))
                .isFalse();
    }

    @Test
    void isLinkedChain_certificateNotIssuedByTheNext_returnsFalse() {
        var leaf = pki.validP256Leaf().certificate();
        var otherIntermediate = pki.chainWithIntermediate().certificates().get(1);
        assertThat(SigningCertificateChecks.isLinkedChain(List.of(leaf, otherIntermediate), NOW)).isFalse();
    }

    @Test
    void isLinkedChain_nextIsNotACa_returnsFalse() {
        var leaf = pki.chainWithIntermediate().certificates().getFirst();
        assertThat(SigningCertificateChecks.isLinkedChain(List.of(leaf, pki.validP256Leaf().certificate()), NOW))
                .isFalse();
    }

    @Test
    void isLinkedChain_forgedIssuerWithTheSameName_returnsFalse() {
        assertThat(SigningCertificateChecks.isLinkedChain(
                List.of(pki.validP256Leaf().certificate(), pki.forgedSelfIssuedCertificate()), NOW)).isFalse();
    }
}
