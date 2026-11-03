package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.TenantConfigMissingException;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyCertificatePort;
import es.in2.issuer.backend.signing.domain.util.OwnKeyCertificates;
import es.in2.issuer.backend.signing.domain.util.OwnKeyTestPki;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class OwnKeySigningConfigLoaderImplTest {

    private static final OwnKeyTestPki PKI = new OwnKeyTestPki();
    private static final String TENANT = "cgcom";

    private final OwnKeyCertificatePort port = mock(OwnKeyCertificatePort.class);
    private final TenantConfigService tenantConfig = mock(TenantConfigService.class);
    private OwnKeySigningConfigLoaderImpl loader;

    @BeforeEach
    void setUp() {
        loader = new OwnKeySigningConfigLoaderImpl(providerOf(port), tenantConfig);
        lenient().when(tenantConfig.getStringOrThrow("admin_organization_id"))
                .thenReturn(Mono.just(OwnKeyTestPki.ORGANIZATION_IDENTIFIER));
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<OwnKeyCertificatePort> providerOf(OwnKeyCertificatePort port) {
        ObjectProvider<OwnKeyCertificatePort> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(port);
        return provider;
    }

    private static String pem(X509Certificate... certificates) throws Exception {
        StringBuilder pem = new StringBuilder();
        for (X509Certificate certificate : certificates) {
            pem.append("-----BEGIN CERTIFICATE-----\n")
                    .append(Base64.getMimeEncoder().encodeToString(certificate.getEncoded()))
                    .append("\n-----END CERTIFICATE-----\n");
        }
        return pem.toString();
    }

    private static void assertReason(Throwable error, SigningFailureReason reason) {
        assertThat(error).isInstanceOfSatisfying(SigningException.class, e -> assertThat(e.getReason()).isEqualTo(reason));
    }

    @Test
    void load_certificateOfTheTenantOrganization_namesTheKeyAfterItAndKeepsTheChain() throws Exception {
        var chain = PKI.chainWithIntermediate().certificates();
        when(port.findCertificateChainPem(TENANT)).thenReturn(Mono.just(pem(chain.get(0), chain.get(1))));

        StepVerifier.create(loader.load(TENANT))
                .assertNext(config -> {
                    assertThat(config.kmsKeyRef()).isEqualTo(OwnKeyCertificates.keyAlias(chain.get(0)));
                    assertThat(config.algorithm()).isEqualTo("ES256");
                    assertThat(config.certificateChain()).isEqualTo(OwnKeyCertificates.toX5c(chain));
                })
                .verifyComplete();
    }

    @Test
    void load_noCertificateForTheTenant_isNoConfiguration() {
        when(port.findCertificateChainPem(TENANT)).thenReturn(Mono.empty());

        StepVerifier.create(loader.load(TENANT))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.NO_CONFIGURATION))
                .verify();
    }

    @Test
    void load_certificateOfAnotherOrganization_isNoConfiguration() throws Exception {
        var leaf = PKI.leafWithOrganizationIdentifier("VATES-B60645900").certificate();
        when(port.findCertificateChainPem(TENANT)).thenReturn(Mono.just(pem(leaf)));

        StepVerifier.create(loader.load(TENANT))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.NO_CONFIGURATION))
                .verify();
    }

    @Test
    void load_organizationOnlyInTheIssuerOfTheLeaf_isCertificateInvalid() throws Exception {
        var leaf = PKI.leafWithOrganizationIdentifierOnlyInItsIssuer().certificate();
        when(port.findCertificateChainPem(TENANT)).thenReturn(Mono.just(pem(leaf)));

        StepVerifier.create(loader.load(TENANT))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
    }

    @Test
    void load_rsaLeaf_isCertificateInvalid() throws Exception {
        when(port.findCertificateChainPem(TENANT)).thenReturn(Mono.just(pem(PKI.rsaLeaf().certificate())));

        StepVerifier.create(loader.load(TENANT))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
    }

    @Test
    void load_unreadablePem_isCertificateInvalid() {
        when(port.findCertificateChainPem(TENANT)).thenReturn(Mono.just("not a certificate"));

        StepVerifier.create(loader.load(TENANT))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.CERTIFICATE_INVALID))
                .verify();
    }

    @Test
    void load_tenantWithoutOrganization_isNoConfiguration() throws Exception {
        when(port.findCertificateChainPem(TENANT)).thenReturn(Mono.just(pem(PKI.validP256Leaf().certificate())));
        when(tenantConfig.getStringOrThrow("admin_organization_id"))
                .thenReturn(Mono.error(new TenantConfigMissingException(TENANT, "admin_organization_id")));

        StepVerifier.create(loader.load(TENANT))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.NO_CONFIGURATION))
                .verify();
    }

    @Test
    void load_certificateReadFails_reachesTheCallerUnchanged() {
        var failure = new SigningException(SigningFailureReason.PROVIDER_UNAVAILABLE, "s3 down");
        when(port.findCertificateChainPem(TENANT)).thenReturn(Mono.error(failure));

        StepVerifier.create(loader.load(TENANT))
                .expectErrorSatisfies(e -> assertThat(e).isSameAs(failure))
                .verify();
    }

    @Test
    void load_certificatesNotConfiguredOnTheIssuer_isNoConfiguration() {
        var withoutPort = new OwnKeySigningConfigLoaderImpl(providerOf(null), tenantConfig);

        StepVerifier.create(withoutPort.load(TENANT))
                .expectErrorSatisfies(e -> assertReason(e, SigningFailureReason.NO_CONFIGURATION))
                .verify();
        verifyNoInteractions(port);
    }
}
