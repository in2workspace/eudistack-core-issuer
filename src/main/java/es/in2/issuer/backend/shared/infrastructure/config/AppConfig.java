package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.AppProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.IssuerIdentityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

import java.net.URI;

@Configuration
@RequiredArgsConstructor
public class AppConfig implements IssuerProperties {

    private final AppProperties appProperties;
    private final IssuerIdentityProperties issuerIdentityProperties;

    public String getIssuerBackendUrl() {
        return appProperties.url();
    }

    public String getIssuerInternalUrl() {
        String internal = appProperties.internalUrl();
        return (internal != null && !internal.isBlank()) ? internal : appProperties.url();
    }

    public String getIssuerFrontendUrl() {
        return appProperties.issuerFrontendUrl();
    }

    public String getWalletFrontendUrl() {
        return appProperties.walletUrl();
    }

    public String getCredentialSubjectDidKey() {
        return issuerIdentityProperties.credentialSubjectDidKey();
    }

    public String getCryptoPrivateKey() {
        return issuerIdentityProperties.crypto().privateKey();
    }

    public String getVerifierUrl() {
        return appProperties.verifierUrl();
    }

    public String getVerifierInternalUrl() {
        String internal = appProperties.verifierInternalUrl();
        return (internal != null && !internal.isBlank()) ? internal : appProperties.verifierUrl();
    }

    public String getDefaultLang() {
        return appProperties.defaultLang();
    }

    public String getAdminOrganizationId() {
        return appProperties.adminOrganizationId();
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

    @Override
    public boolean isVerifierIssuer(String issuer) {
        String configuredUrl = getVerifierUrl();
        if (configuredUrl.equals(issuer)) {
            return true;
        }
        return baseOriginMatches(configuredUrl, issuer);
    }

    @Override
    public boolean isIssuerBackendIssuer(String issuer) {
        String configuredUrl = getIssuerBackendUrl();
        if (configuredUrl.equals(issuer)) {
            return true;
        }
        return baseOriginMatches(configuredUrl, issuer);
    }

    /**
     * Compares scheme + base domain (host minus first label) + port.
     * e.g. https://altia.127.0.0.1.nip.io:4444 and https://cgcom.127.0.0.1.nip.io:4444
     * both have base origin https://127.0.0.1.nip.io:4444 → match.
     */
    private boolean baseOriginMatches(String url1, String url2) {
        try {
            URI u1 = URI.create(url1);
            URI u2 = URI.create(url2);
            if (!u1.getScheme().equals(u2.getScheme())) return false;
            if (u1.getPort() != u2.getPort()) return false;
            String base1 = stripFirstLabel(u1.getHost());
            String base2 = stripFirstLabel(u2.getHost());
            return base1 != null && base1.equals(base2);
        } catch (Exception e) {
            return false;
        }
    }

    private String stripFirstLabel(String host) {
        if (host == null) return null;
        int dot = host.indexOf('.');
        return (dot >= 0) ? host.substring(dot + 1) : null;
    }
}
