package es.in2.issuer.backend.signing.domain.onboarding;

import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class OwnKeyCertificateValidatorTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");

    private final OwnKeyTestPki pki = new OwnKeyTestPki();

    private ValidatedOwnKeyCertificate validate(List<X509Certificate> chain, OnboardingPolicy policy) {
        return OwnKeyCertificateValidator.validate(chain, policy, NOW);
    }

    private ValidatedOwnKeyCertificate validate(X509Certificate leaf) {
        return validate(List.of(leaf), OnboardingPolicy.nonProduction());
    }

    private OnboardingPolicy production() {
        return new OnboardingPolicy(true, pki.rootCertificate(), OwnKeyTestPki.ORGANIZATION_IDENTIFIER);
    }

    private RejectionReason rejectionOf(ThrowingCallable validation) {
        return catchThrowableOfType(OnboardingRejectedException.class, validation).getReason();
    }

    @Test
    void validate_p256CertificateIssuedByACa_isAccepted() {
        var validated = validate(pki.validP256Leaf().certificate());

        assertThat(validated.leaf()).isEqualTo(pki.validP256Leaf().certificate());
    }

    @Test
    void validate_leafWithSigningExtensions_isAccepted() {
        assertThat(validate(pki.signingLeafWithExtensions().certificate()).chain()).hasSize(1);
    }

    @Test
    void validate_rsaCertificate_isRejectedAsInvalidKey() {
        assertThat(rejectionOf(() -> validate(pki.rsaLeaf().certificate()))).isEqualTo(RejectionReason.INVALID_KEY);
    }

    @Test
    void validate_p384Certificate_isRejectedAsInvalidKey() {
        assertThat(rejectionOf(() -> validate(pki.p384Leaf().certificate()))).isEqualTo(RejectionReason.INVALID_KEY);
    }

    @Test
    void validate_expiredCertificate_isRejectedEvenOutsideProduction() {
        assertThatThrownBy(() -> validate(pki.expiredLeaf().certificate()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessage("the certificate is not valid now");
    }

    @Test
    void validate_expiredIntermediate_isRejectedEvenOutsideProduction() {
        var chain = pki.chainWithExpiredIntermediate().certificates();

        assertThatThrownBy(() -> validate(chain, OnboardingPolicy.nonProduction()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessage("certificate 2 of the chain is not valid now");
    }

    @Test
    void validate_chainWithIntermediate_isAccepted() {
        var chain = pki.chainWithIntermediate().certificates();

        assertThat(validate(chain, OnboardingPolicy.nonProduction()).chain()).hasSize(2);
    }

    @Test
    void validate_certificateThatIsACa_isRejected() {
        assertThatThrownBy(() -> validate(pki.caLeaf().certificate()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("CA certificate");
    }

    @Test
    void validate_keyUsageWithoutSigning_isRejected() {
        assertThatThrownBy(() -> validate(pki.certSignOnlyLeaf().certificate()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("key usage does not allow signing");
    }

    @Test
    void validate_chainWhoseCertificatesAreNotLinked_isRejected() {
        var leafOfIntermediate = pki.chainWithIntermediate().certificates().getFirst();

        assertThatThrownBy(() -> validate(List.of(leafOfIntermediate, pki.rootCertificate()),
                OnboardingPolicy.nonProduction()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessage("certificate 1 of the chain is not issued by certificate 2");
    }

    @Test
    void validate_issuerThatIsNotACa_isRejected() {
        var chain = pki.chainWithNonCaIssuer().certificates();

        assertThatThrownBy(() -> validate(chain, OnboardingPolicy.nonProduction()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessage("certificate 2 of the chain is not a CA");
    }

    @Test
    void validate_qcpNQscdPolicy_isRejected() {
        assertThatThrownBy(() -> validate(pki.leafWithPolicy("0.4.0.194112.1.2").certificate()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("QCP-n-qscd or QCP-l-qscd");
    }

    @Test
    void validate_qcpLQscdPolicy_isRejected() {
        assertThatThrownBy(() -> validate(pki.leafWithPolicy("0.4.0.194112.1.3").certificate()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("QCP-n-qscd or QCP-l-qscd");
    }

    @Test
    void validate_qcSscdStatement_isRejected() {
        assertThatThrownBy(() -> validate(pki.leafWithQcSscdStatement().certificate()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessageContaining("QcSSCD");
    }

    @Test
    void validate_qcpLWithoutQscd_isAccepted() {
        assertThat(validate(pki.leafWithPolicy("0.4.0.194112.1.1").certificate()).chain()).hasSize(1);
    }

    @Test
    void validate_selfSignedOutsideProduction_isAccepted() {
        assertThat(validate(pki.selfSignedLeaf().certificate()).chain()).hasSize(1);
    }

    @Test
    void validate_selfSignedInProduction_isRejected() {
        var policy = new OnboardingPolicy(true, pki.rootCertificate(), OwnKeyTestPki.ORGANIZATION_IDENTIFIER);

        assertThatThrownBy(() -> validate(List.of(pki.selfSignedLeaf().certificate()), policy))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessage("the certificate is self-signed (production)");
    }

    @Test
    void validate_productionWithTheAgreedCaAndOrganization_isAccepted() {
        assertThat(validate(List.of(pki.validP256Leaf().certificate()), production()).chain()).hasSize(1);
    }

    @Test
    void validate_chainEndingInAnIntermediateTrustAnchor_isAccepted() {
        var chain = pki.chainWithIntermediate().certificates();
        var policy = new OnboardingPolicy(false, chain.get(1), null);

        assertThat(validate(chain, policy).chain()).hasSize(2);
    }

    @Test
    void validate_rootAsTrustAnchorOfAChainWithIntermediate_isAccepted() {
        var chain = pki.chainWithIntermediate().certificates();
        var policy = new OnboardingPolicy(false, pki.rootCertificate(), null);

        assertThat(validate(chain, policy).chain()).hasSize(2);
    }

    @Test
    void validate_trustAnchorOfAnotherCa_isRejected() {
        var policy = new OnboardingPolicy(false, new OwnKeyTestPki().rootCertificate(), null);

        assertThatThrownBy(() -> validate(List.of(pki.validP256Leaf().certificate()), policy))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessage("the chain does not end in the agreed CA");
    }

    @Test
    void validate_trustAnchorThatIsNotACa_isRejected() {
        var policy = new OnboardingPolicy(false, pki.validP256Leaf().certificate(), null);

        assertThat(rejectionOf(() -> validate(List.of(pki.validP256Leaf().certificate()), policy)))
                .isEqualTo(RejectionReason.INVALID_CERTIFICATE);
    }

    @Test
    void validate_organizationIdentifierOfAnotherOrganization_isRejected() {
        var leaf = pki.leafWithOrganizationIdentifier("VATES-Q9999999Z").certificate();

        assertThatThrownBy(() -> validate(List.of(leaf), production()))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessage("the certificate organizationIdentifier is 'VATES-Q9999999Z', expected 'VATES-Q0000000X'");
    }

    @Test
    void validate_certificateWithoutOrganizationIdentifier_isRejectedWhenOneIsExpected() {
        var leaf = pki.leafWithoutOrganizationIdentifier().certificate();
        var policy = new OnboardingPolicy(false, null, OwnKeyTestPki.ORGANIZATION_IDENTIFIER);

        assertThatThrownBy(() -> validate(List.of(leaf), policy))
                .isInstanceOf(OnboardingRejectedException.class)
                .hasMessage("the certificate organizationIdentifier is 'none', expected 'VATES-Q0000000X'");
    }

    @Test
    void policy_productionWithoutTrustAnchor_isAUsageError() {
        assertThatThrownBy(() -> new OnboardingPolicy(true, null, OwnKeyTestPki.ORGANIZATION_IDENTIFIER))
                .isInstanceOf(OnboardingUsageException.class);
    }

    @Test
    void policy_productionWithoutOrganizationIdentifier_isAUsageError() {
        assertThatThrownBy(() -> new OnboardingPolicy(true, pki.rootCertificate(), " "))
                .isInstanceOf(OnboardingUsageException.class);
    }

    @Test
    void validated_exposesTheChainAsX5cAndTheHashesOfTheLeaf() throws Exception {
        var leaf = pki.validP256Leaf();
        var validated = validate(leaf.certificate());

        assertThat(validated.chainBase64()).containsExactly(Base64.getEncoder().encodeToString(leaf.certificate().getEncoded()));
        assertThat(validated.spkiDer()).isEqualTo(leaf.publicKeyDer());
        assertThat(validated.spkiSha256Hex()).hasSize(64);
        assertThat(validated.certificateSha256Hex()).hasSize(64).isNotEqualTo(validated.spkiSha256Hex());
    }

    @Test
    void parsePemChain_aBundleOfTwoCertificates_keepsTheOrder() throws Exception {
        var chain = pki.chainWithIntermediate().certificates();
        String pem = toPem(chain.get(0)) + toPem(chain.get(1));

        assertThat(OwnKeyCertificateValidator.parsePemChain(pem)).containsExactlyElementsOf(chain);
    }

    @Test
    void parsePemChain_textThatIsNotACertificate_isRejected() {
        assertThat(rejectionOf(() -> OwnKeyCertificateValidator.parsePemChain("not a certificate")))
                .isEqualTo(RejectionReason.INVALID_CERTIFICATE);
    }

    @Test
    void parseBase64Chain_garbage_isRejected() {
        assertThat(rejectionOf(() -> OwnKeyCertificateValidator.parseBase64Chain(List.of("AAAA"))))
                .isEqualTo(RejectionReason.INVALID_CERTIFICATE);
    }

    static String toPem(X509Certificate certificate) throws Exception {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
    }
}
