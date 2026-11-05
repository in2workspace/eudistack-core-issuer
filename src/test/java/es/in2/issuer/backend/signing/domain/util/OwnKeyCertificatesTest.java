package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.signing.domain.exception.CertificateCheckException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.CertificateCheck;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OwnKeyCertificatesTest {

    private static final OwnKeyTestPki PKI = new OwnKeyTestPki();

    static String pem(X509Certificate... certificates) throws Exception {
        StringBuilder pem = new StringBuilder();
        for (X509Certificate certificate : certificates) {
            pem.append("-----BEGIN CERTIFICATE-----\n")
                    .append(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded()))
                    .append("\n-----END CERTIFICATE-----\n");
        }
        return pem.toString();
    }

    @Test
    void parsePemChain_leafAndIntermediate_keepsTheirOrder() throws Exception {
        var chain = PKI.chainWithIntermediate().certificates();

        assertThat(OwnKeyCertificates.parsePemChain(pem(chain.get(0), chain.get(1)))).containsExactlyElementsOf(chain);
    }

    @Test
    void parsePemChain_noCertificate_isCertificateInvalid() {
        assertThatThrownBy(() -> OwnKeyCertificates.parsePemChain(""))
                .isInstanceOfSatisfying(SigningException.class,
                        e -> assertThat(e.getReason()).isEqualTo(SigningFailureReason.CERTIFICATE_INVALID));
    }

    @Test
    void parsePemChain_notAPem_isCertificateInvalid() {
        assertThatThrownBy(() -> OwnKeyCertificates.parsePemChain("""
                -----BEGIN CERTIFICATE-----
                not base64
                -----END CERTIFICATE-----
                """))
                .isInstanceOfSatisfying(SigningException.class,
                        e -> assertThat(e.getReason()).isEqualTo(SigningFailureReason.CERTIFICATE_INVALID));
    }

    @Test
    void toX5c_isTheStandardBase64OfEachDerCertificate() throws Exception {
        var chain = PKI.chainWithIntermediate().certificates();

        assertThat(OwnKeyCertificates.toX5c(chain)).containsExactly(
                Base64.getEncoder().encodeToString(chain.get(0).getEncoded()),
                Base64.getEncoder().encodeToString(chain.get(1).getEncoded()));
    }

    @Test
    void subjectOrganizationIdentifier_readsTheSubject() {
        var leaf = PKI.leafWithOrganizationIdentifier("VATES-B60645900").certificate();

        assertThat(OwnKeyCertificates.subjectOrganizationIdentifier(leaf)).contains("VATES-B60645900");
    }

    @Test
    void subjectOrganizationIdentifier_onlyInTheIssuer_isEmpty() {
        var leaf = PKI.leafWithOrganizationIdentifierOnlyInItsIssuer().certificate();

        assertThat(leaf.getIssuerX500Principal().toString()).contains(OwnKeyTestPki.ORGANIZATION_IDENTIFIER);
        assertThat(OwnKeyCertificates.subjectOrganizationIdentifier(leaf)).isEmpty();
    }

    @Test
    void subjectOrganizationIdentifier_insideAMultiValuedRdn_isRead() {
        var leaf = PKI.leafWithOrganizationIdentifierInAMultiValuedRdn("VATES-B60645900").certificate();

        assertThat(OwnKeyCertificates.subjectOrganizationIdentifier(leaf)).contains("VATES-B60645900");
    }

    /** The first one would otherwise win, and a verifier reading the other would attribute it to another organization. */
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void subjectOrganizationIdentifier_twoInTheSubject_isRejected(boolean sameRdn) {
        var leaf = PKI.leafWithTwoOrganizationIdentifiers(OwnKeyTestPki.ORGANIZATION_IDENTIFIER, "VATES-B60645900",
                sameRdn).certificate();

        assertThatThrownBy(() -> OwnKeyCertificates.subjectOrganizationIdentifier(leaf))
                .isInstanceOfSatisfying(CertificateCheckException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(SigningFailureReason.CERTIFICATE_INVALID);
                    assertThat(e.getCheck()).isEqualTo(CertificateCheck.DUPLICATED_ORGANIZATION_IDENTIFIER);
                });
    }

    @Test
    void subjectOrganizationIdentifier_noneInTheCertificate_isEmpty() {
        var leaf = PKI.leafWithoutOrganizationIdentifier().certificate();

        assertThat(OwnKeyCertificates.subjectOrganizationIdentifier(leaf)).isEmpty();
    }

    @Test
    void keyAlias_isTheSerialNumberInUppercaseHexWithoutLeadingZeros() {
        var leaf = PKI.leafWithSerialNumber(new BigInteger("0a1b2c3d4e5f60718293a4b5c6d7e8f9", 16)).certificate();

        assertThat(OwnKeyCertificates.keyAlias(leaf)).isEqualTo("alias/A1B2C3D4E5F60718293A4B5C6D7E8F9");
    }

    @Test
    void keyAlias_sameKeyInAnotherCertificate_isAnotherAlias() {
        var leaf = PKI.validP256Leaf();
        X509Certificate renewed = PKI.certificateFor(leaf.keyPair().getPublic());

        assertThat(OwnKeyCertificates.keyAlias(renewed)).isNotEqualTo(OwnKeyCertificates.keyAlias(leaf.certificate()));
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void keyAlias_nonPositiveSerialNumber_isRejected(long serialNumber) {
        var leaf = PKI.leafWithSerialNumber(BigInteger.valueOf(serialNumber)).certificate();

        assertThatThrownBy(() -> OwnKeyCertificates.keyAlias(leaf))
                .isInstanceOfSatisfying(CertificateCheckException.class,
                        e -> assertThat(e.getCheck()).isEqualTo(CertificateCheck.NON_POSITIVE_SERIAL_NUMBER));
    }
}
