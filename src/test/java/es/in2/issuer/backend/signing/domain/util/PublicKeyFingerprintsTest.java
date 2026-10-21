package es.in2.issuer.backend.signing.domain.util;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PublicKeyFingerprintsTest {

    private final OwnKeyTestPki pki = new OwnKeyTestPki();

    @Test
    void spkiSha256_certificate_isLowercaseHexSha256OfTheSpki() throws Exception {
        var leaf = pki.validP256Leaf();

        String fingerprint = PublicKeyFingerprints.spkiSha256(leaf.certificate());

        String expected = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(leaf.publicKeyDer()));
        assertThat(fingerprint).isEqualTo(expected).hasSize(64).isLowerCase();
    }

    @Test
    void spkiSha256_certificateAndItsDerPublicKey_areEqual() {
        var leaf = pki.validP256Leaf();

        assertThat(PublicKeyFingerprints.spkiSha256(leaf.publicKeyDer()))
                .isEqualTo(PublicKeyFingerprints.spkiSha256(leaf.certificate()));
    }

    @Test
    void spkiSha256_rsaCertificateAndItsDerPublicKey_areEqual() {
        var leaf = pki.rsaLeaf();

        assertThat(PublicKeyFingerprints.spkiSha256(leaf.publicKeyDer()))
                .isEqualTo(PublicKeyFingerprints.spkiSha256(leaf.certificate()));
    }

    @Test
    void spkiSha256_differentKeys_differ() {
        assertThat(PublicKeyFingerprints.spkiSha256(pki.validP256Leaf().certificate()))
                .isNotEqualTo(PublicKeyFingerprints.spkiSha256(pki.unrelatedPublicKeyDer()));
    }

    @Test
    void spkiSha256_malformedDer_throws() {
        byte[] garbage = {0x01, 0x02, 0x03, 0x04};

        assertThatThrownBy(() -> PublicKeyFingerprints.spkiSha256(garbage))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SPKI");
    }

    @Test
    void spkiSha256_truncatedDer_throws() {
        byte[] der = pki.validP256Leaf().publicKeyDer();
        byte[] truncated = java.util.Arrays.copyOf(der, der.length - 5);

        assertThatThrownBy(() -> PublicKeyFingerprints.spkiSha256(truncated))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void spkiSha256_emptyDer_throws() {
        assertThatThrownBy(() -> PublicKeyFingerprints.spkiSha256(new byte[0]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void spkiSha256_nullDer_throws() {
        assertThatThrownBy(() -> PublicKeyFingerprints.spkiSha256((byte[]) null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void spkiSha256_nullCertificate_throws() {
        assertThatThrownBy(() -> PublicKeyFingerprints.spkiSha256((java.security.cert.X509Certificate) null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
