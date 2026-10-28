package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BouncyCastleCertificateExtensionsTest {

    private final OwnKeyTestPki pki = new OwnKeyTestPki();
    private final BouncyCastleCertificateExtensions extensions = new BouncyCastleCertificateExtensions();

    @Test
    void policyIdentifiers_readsTheOidsOfTheCertificatePolicies() {
        var leaf = pki.leafWithPolicy("0.4.0.194112.1.2").certificate();

        assertThat(extensions.policyIdentifiers(leaf)).containsExactly("0.4.0.194112.1.2");
    }

    @Test
    void qcStatementIdentifiers_readsTheOidsOfTheStatements() {
        var leaf = pki.leafWithQcSscdStatement().certificate();

        assertThat(extensions.qcStatementIdentifiers(leaf)).contains("0.4.0.1862.1.4");
    }

    @Test
    void organizationIdentifier_readsItFromTheSubject() {
        var leaf = pki.leafWithOrganizationIdentifier("VATES-B00000000").certificate();

        assertThat(extensions.organizationIdentifier(leaf)).contains("VATES-B00000000");
    }

    @Test
    void certificateWithoutTheExtensions_hasNoneOfThem() {
        var leaf = pki.leafWithoutOrganizationIdentifier().certificate();

        assertThat(extensions.policyIdentifiers(leaf)).isEmpty();
        assertThat(extensions.qcStatementIdentifiers(leaf)).isEmpty();
        assertThat(extensions.organizationIdentifier(leaf)).isEmpty();
    }
}
