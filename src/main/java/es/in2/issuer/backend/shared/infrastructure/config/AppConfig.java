package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.AppProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.IssuerIdentityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

/**
 * Application configuration exposing settings that are orthogonal to URL
 * resolution.
 *
 * <p>Public / verifier URLs are NOT exposed from here. Code that needs to
 * build a public URL must inject
 * {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver} and derive it
 * from the current {@link org.springframework.web.server.ServerWebExchange}
 * (EUDI-017).
 */
@Configuration
@RequiredArgsConstructor
public class AppConfig implements IssuerProperties {

    private final AppProperties appProperties;
    private final IssuerIdentityProperties issuerIdentityProperties;

    public String getIssuerInternalUrl() {
        return appProperties.internalUrl();
    }

    public String getCryptoPrivateKey() {
        return issuerIdentityProperties.crypto().privateKey();
    }

    // Returned URL is consumed by VerifierHealthIndicator and UrlResolver to
    // probe / reach the verifier over the intra-VPC network.
    public String getVerifierInternalUrl() {
        return appProperties.verifierInternalUrl();
    }

    public String getDefaultLang() {
        return appProperties.defaultLang();
    }

    public String getSysTenant() {
        return appProperties.sysTenant();
    }

    public String getManagementTokenOrgIdJsonPath() {
        return appProperties.managementToken() != null
                ? appProperties.managementToken().orgIdJsonPath()
                : "vc.credentialSubject.mandate.mandator.organizationIdentifier";
    }

    public String getManagementTokenAdminPowerFunction() {
        return appProperties.managementToken() != null
                ? appProperties.managementToken().adminPowerFunction()
                : "Onboarding";
    }

    public String getManagementTokenAdminPowerAction() {
        return appProperties.managementToken() != null
                ? appProperties.managementToken().adminPowerAction()
                : "Execute";
    }
}
