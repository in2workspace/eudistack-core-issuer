package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.properties.AppProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.CorsProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.IssuerIdentityProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME;
import static es.in2.issuer.backend.shared.domain.util.Constants.VERIFIABLE_CREDENTIAL_JWT_CACHE_EXPIRATION_TIME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AppConfigTest {

    @Mock
    private AppProperties appProperties;

    @Mock
    private IssuerIdentityProperties issuerIdentityProperties;

    @Mock
    private CorsProperties corsProperties;

    @InjectMocks
    private AppConfig appConfig;

    @Test
    void testGetIssuerBackendUrl() {
        String expected = "https://api.example.com";
        when(appProperties.url()).thenReturn(expected);

        assertEquals(expected, appConfig.getIssuerBackendUrl());
    }

    @Test
    void testGetIssuerFrontendUrl() {
        String expected = "https://ui.example.com";
        when(appProperties.issuerFrontendUrl()).thenReturn(expected);

        assertEquals(expected, appConfig.getIssuerFrontendUrl());
    }

    @Test
    void testGetKnowledgeBaseUploadCertificationGuideUrl() {
        String expected = "https://knowledge.example.com";
        AppProperties.KnowledgeBase knowledgeBase = mock(AppProperties.KnowledgeBase.class);
        when(appProperties.knowledgeBase()).thenReturn(knowledgeBase);
        when(knowledgeBase.uploadCertificationGuideUrl()).thenReturn(expected);

        assertEquals(expected, appConfig.getKnowledgeBaseUploadCertificationGuideUrl());
    }

    @Test
    void testGetWalletFrontendUrl() {
        String expected = "https://wallet.example.com";
        when(appProperties.walletUrl()).thenReturn(expected);

        assertEquals(expected, appConfig.getWalletFrontendUrl());
    }

    @Test
    void testGetCacheLifetimeForCredentialOffer() {
        assertEquals(10L, (long) CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME);
    }

    @Test
    void testGetCacheLifetimeForVerifiableCredential() {
        assertEquals(10L, (long) VERIFIABLE_CREDENTIAL_JWT_CACHE_EXPIRATION_TIME);
    }

    @Test
    void getExternalCorsAllowedOrigins_returnsConfiguredOrigins() {
        List<String> expected = List.of("https://example.com", "https://another.com");
        when(corsProperties.externalAllowedOrigins()).thenReturn(expected);

        assertEquals(expected, appConfig.getExternalCorsAllowedOrigins());
    }

    @Test
    void getDefaultCorsAllowedOrigins_returnsConfiguredOrigins() {
        List<String> expected = List.of("https://default.com", "https://default2.com");
        when(corsProperties.defaultAllowedOrigins()).thenReturn(expected);

        assertEquals(expected, appConfig.getDefaultCorsAllowedOrigins());
    }

    @Test
    void getExternalCorsAllowedOrigins_whenNoOriginsConfigured_returnsEmptyList() {
        when(corsProperties.externalAllowedOrigins()).thenReturn(Collections.emptyList());

        assertTrue(appConfig.getExternalCorsAllowedOrigins().isEmpty());
    }

    @Test
    void getDefaultCorsAllowedOrigins_whenNoOriginsConfigured_returnsEmptyList() {
        when(corsProperties.defaultAllowedOrigins()).thenReturn(Collections.emptyList());

        assertTrue(appConfig.getDefaultCorsAllowedOrigins().isEmpty());
    }

    @Test
    void getAdminOrganizationId_returnsConfiguredValue() {
        String expected = "admin-org-123";
        when(appProperties.adminOrganizationId()).thenReturn(expected);

        assertEquals(expected, appConfig.getAdminOrganizationId());
    }

    @Test
    void getSysTenant_returnsConfiguredValue() {
        String expected = "sys-tenant";
        when(appProperties.sysTenant()).thenReturn(expected);

        assertEquals(expected, appConfig.getSysTenant());
    }
}
