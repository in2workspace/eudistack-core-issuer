package es.in2.issuer.backend.signing.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.TenantConfigMissingException;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.signing.domain.exception.CertificateCheckException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.CertificateCheck;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningCurve;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.service.OwnKeySigningConfigLoader;
import es.in2.issuer.backend.signing.domain.spi.OwnKeyCertificatePort;
import es.in2.issuer.backend.signing.domain.util.OwnKeyCertificates;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * The certificate comes from {@link OwnKeyCertificatePort}; the configuration holds its chain and the alias
 * of the KMS key derived from it. The certificate must belong to the organization of the tenant, the
 * {@code admin_organization_id} of its configuration: the subject's {@code organizationIdentifier} of the
 * leaf, the same value that becomes the issuer of the credentials, must be equal to it.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OwnKeySigningConfigLoaderImpl implements OwnKeySigningConfigLoader {

    static final String TENANT_ORGANIZATION_KEY = "admin_organization_id";

    /** The port exists only when {@code issuer.signing.certificates.arn} is set. */
    private final ObjectProvider<OwnKeyCertificatePort> certificatePort;
    private final TenantConfigService tenantConfigService;

    @Override
    public Mono<OwnKeySigningConfig> load(String tenant) {
        OwnKeyCertificatePort port = certificatePort.getIfAvailable();
        if (port == null) {
            log.error("Own-key certificates are not configured on this issuer tenant={}", tenant);
            return Mono.error(noConfiguration("Own-key certificates are not configured on this issuer"));
        }
        return port.findCertificateChainPem(tenant)
                .switchIfEmpty(Mono.error(() -> {
                    log.error("OWN_KEY_CERTIFICATE_MISSING tenant={}", tenant);
                    return noConfiguration("The tenant has no own-key certificate");
                }))
                .map(OwnKeyCertificates::parsePemChain)
                .zipWith(tenantOrganization(tenant))
                .map(chainAndOrganization -> toConfig(tenant, chainAndOrganization.getT1(),
                        chainAndOrganization.getT2()));
    }

    private Mono<String> tenantOrganization(String tenant) {
        return tenantConfigService.getStringOrThrow(TENANT_ORGANIZATION_KEY)
                .onErrorMap(TenantConfigMissingException.class, e -> {
                    log.error("Tenant has no {} to check its own-key certificate against tenant={}",
                            TENANT_ORGANIZATION_KEY, tenant);
                    return noConfiguration("The tenant has no organization to check its certificate against");
                });
    }

    private static OwnKeySigningConfig toConfig(String tenant, List<X509Certificate> chain, String organization) {
        X509Certificate leaf = chain.getFirst();
        String certificateOrganization = OwnKeyCertificates.subjectOrganizationIdentifier(leaf)
                .orElseThrow(() -> new CertificateCheckException(CertificateCheck.NO_ORGANIZATION_IDENTIFIER,
                        "The own-key certificate has no organizationIdentifier in its subject"));
        if (!certificateOrganization.equals(organization)) {
            log.error("CERTIFICATE_TENANT_MISMATCH tenant={} expected={} certificate={}",
                    tenant, organization, certificateOrganization);
            throw new CertificateCheckException(SigningFailureReason.NO_CONFIGURATION,
                    CertificateCheck.ORGANIZATION_MISMATCH, "The own-key certificate belongs to another organization",
                    null);
        }
        // SigningCurve lists the curves an own key may use: only P-256 for now.
        if (SigningCurve.of(leaf).isEmpty()) {
            throw new CertificateCheckException(CertificateCheck.NOT_P256,
                    "The own-key certificate does not hold a key on a supported curve (P-256)");
        }
        return new OwnKeySigningConfig(OwnKeyCertificates.keyAlias(leaf), OwnKeySigningConfig.ES256,
                OwnKeyCertificates.toX5c(chain));
    }

    private static SigningException noConfiguration(String message) {
        return new SigningException(SigningFailureReason.NO_CONFIGURATION, message);
    }
}
