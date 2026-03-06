package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.AppProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.IssuerIdentityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class AppConfig implements IssuerProperties {

    private final AppProperties appProperties;
    private final IssuerIdentityProperties issuerIdentityProperties;
    private final CorsProperties corsProperties;

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

    public String getKnowledgebaseWalletUrl() {
        return appProperties.knowledgeBase().walletGuideUrl();
    }

    public String getWalletFrontendUrl() {
        return appProperties.walletUrl();
    }

    public String getKnowledgeBaseUploadCertificationGuideUrl() {
        return appProperties.knowledgeBase().uploadCertificationGuideUrl();
    }

    public String getCredentialSubjectDidKey() {
        return issuerIdentityProperties.credentialSubjectDidKey();
    }

    public String getJwtCredential() {
        return issuerIdentityProperties.jwtCredential();
    }

    public String getCryptoPrivateKey() {
        return issuerIdentityProperties.crypto().privateKey();
    }

    public List<String> getExternalCorsAllowedOrigins() {
        return corsProperties.externalAllowedOrigins();
    }

    public List<String> getDefaultCorsAllowedOrigins() {
        return corsProperties.defaultAllowedOrigins();
    }

    public String getVerifierUrl() {
        return appProperties.verifierUrl();
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
}
