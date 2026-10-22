package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StoredCertificateInfoTest {

    private final OwnKeyTestPki pki = new OwnKeyTestPki();

    static OwnKeySigningConfig configOf(List<String> chain) {
        return new OwnKeySigningConfig("arn:aws:kms:eu-west-1:111122223333:key/k", "ES256", chain);
    }

    static String b64(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void from_storedChain_buildsCertificateInfoFromTheLeaf() {
        X509Certificate leaf = pki.validP256Leaf().certificate();
        List<String> chain = List.of(b64(leaf));

        CertificateInfo info = StoredCertificateInfo.from(configOf(chain), true);

        assertThat(info.certificates()).isEqualTo(chain);
        assertThat(info.subjectDN()).isEqualTo(leaf.getSubjectX500Principal().getName());
        assertThat(info.issuerDN()).isEqualTo(leaf.getIssuerX500Principal().getName());
        assertThat(info.serialNumber()).isEqualTo(leaf.getSerialNumber().toString(16).toUpperCase());
        assertThat(info.keyAlgorithms()).containsExactly("1.2.840.10045.4.3.2");
        assertThat(info.keyLength()).isEqualTo(256);
        assertThat(info.qualifiedSeal()).isTrue();
        assertThat(info.validFrom()).isEqualTo(leaf.getNotBefore().toInstant().toString());
        assertThat(info.validTo()).isEqualTo(leaf.getNotAfter().toInstant().toString());
    }

    @Test
    void from_unparsableLeaf_failsWithCertificateInvalid() {
        var config = configOf(List.of("bm90IGEgY2VydGlmaWNhdGU="));

        assertThatThrownBy(() -> StoredCertificateInfo.from(config, false))
                .isInstanceOfSatisfying(SigningException.class,
                        e -> assertThat(e.getReason()).isEqualTo(SigningFailureReason.CERTIFICATE_INVALID));
    }

    @Test
    void leaf_notBase64_failsWithCertificateInvalid() {
        var config = configOf(List.of("***"));

        assertThatThrownBy(() -> StoredCertificateInfo.leaf(config))
                .isInstanceOfSatisfying(SigningException.class,
                        e -> assertThat(e.getReason()).isEqualTo(SigningFailureReason.CERTIFICATE_INVALID));
    }
}
