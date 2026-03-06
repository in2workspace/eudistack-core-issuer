package es.in2.issuer.backend.shared.infrastructure.config.properties;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AppPropertiesTest {

    @Test
    void appProperties_initializesCorrectly() {
        String appUrl = "https://app-url.com";
        String internalUrl = "https://internal-url.com";
        String issuerFrontendUrl = "https://issuer-frontend-url.com";
        String verifierUrl = "https://verifier-url.com";
        String walletFrontendUrl = "https://wallet-frontend-url.com";
        String defaultLang = "es";
        String adminOrganizationId = "org-admin";
        String sysTenant = "sys-tenant";

        String uploadGuideUrl = "https://upload-guide-url.com";
        String walletGuideUrl = "https://wallet-guide-url.com";

        AppProperties.KnowledgeBase knowledgeBase =
                new AppProperties.KnowledgeBase(uploadGuideUrl, walletGuideUrl);

        AppProperties.ManagementToken managementToken =
                new AppProperties.ManagementToken(
                        "vc.credentialSubject.mandate.mandator.organizationIdentifier",
                        "Onboarding",
                        "Execute");

        // Act
        AppProperties appProperties = new AppProperties(
                appUrl,
                internalUrl,
                issuerFrontendUrl,
                knowledgeBase,
                verifierUrl,
                walletFrontendUrl,
                defaultLang,
                adminOrganizationId,
                sysTenant,
                managementToken
        );

        // Assert
        assertEquals(appUrl, appProperties.url());
        assertEquals(internalUrl, appProperties.internalUrl());
        assertEquals(issuerFrontendUrl, appProperties.issuerFrontendUrl());
        assertEquals(knowledgeBase, appProperties.knowledgeBase());
        assertEquals(verifierUrl, appProperties.verifierUrl());
        assertEquals(walletFrontendUrl, appProperties.walletUrl());
        assertEquals(defaultLang, appProperties.defaultLang());
        assertEquals(adminOrganizationId, appProperties.adminOrganizationId());
        assertEquals(sysTenant, appProperties.sysTenant());
        assertEquals(managementToken, appProperties.managementToken());
    }

    @Test
    void knowledgeBase_initializesCorrectly() {
        // Arrange
        String uploadGuideUrl = "https://upload-guide-url.com";
        String walletGuideUrl = "https://wallet-guide-url.com";

        // Act
        AppProperties.KnowledgeBase knowledgeBase =
                new AppProperties.KnowledgeBase(uploadGuideUrl, walletGuideUrl);

        // Assert
        assertEquals(uploadGuideUrl, knowledgeBase.uploadCertificationGuideUrl());
        assertEquals(walletGuideUrl, knowledgeBase.walletGuideUrl());
    }
}
