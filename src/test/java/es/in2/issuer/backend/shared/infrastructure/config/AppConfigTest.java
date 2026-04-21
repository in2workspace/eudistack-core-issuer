package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.properties.AppProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.IssuerIdentityProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AppConfigTest {

    @Mock
    private AppProperties appProperties;

    @Mock
    private IssuerIdentityProperties issuerIdentityProperties;

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
    void testGetWalletFrontendUrl() {
        String expected = "https://wallet.example.com";
        when(appProperties.walletUrl()).thenReturn(expected);

        assertEquals(expected, appConfig.getWalletFrontendUrl());
    }

    @Test
    void getSysTenant_returnsConfiguredValue() {
        String expected = "sys-tenant";
        when(appProperties.sysTenant()).thenReturn(expected);

        assertEquals(expected, appConfig.getSysTenant());
    }

    @Test
    void isVerifierIssuer_ExactMatch_ReturnsTrue() {
        when(appProperties.verifierUrl()).thenReturn("https://altia.127.0.0.1.nip.io:4444");

        assertTrue(appConfig.isVerifierIssuer("https://altia.127.0.0.1.nip.io:4444"));
    }

    @Test
    void isVerifierIssuer_DifferentSubdomain_ReturnsTrue() {
        when(appProperties.verifierUrl()).thenReturn("https://altia.127.0.0.1.nip.io:4444");

        assertTrue(appConfig.isVerifierIssuer("https://cgcom.127.0.0.1.nip.io:4444"));
    }

    @Test
    void isVerifierIssuer_DifferentBaseDomain_ReturnsFalse() {
        when(appProperties.verifierUrl()).thenReturn("https://altia.127.0.0.1.nip.io:4444");

        assertFalse(appConfig.isVerifierIssuer("https://altia.evil.example.com:4444"));
    }

    @Test
    void isVerifierIssuer_DifferentPort_ReturnsFalse() {
        when(appProperties.verifierUrl()).thenReturn("https://altia.127.0.0.1.nip.io:4444");

        assertFalse(appConfig.isVerifierIssuer("https://altia.127.0.0.1.nip.io:9999"));
    }

    @Test
    void isVerifierIssuer_DifferentScheme_ReturnsFalse() {
        when(appProperties.verifierUrl()).thenReturn("https://altia.127.0.0.1.nip.io:4444");

        assertFalse(appConfig.isVerifierIssuer("http://altia.127.0.0.1.nip.io:4444"));
    }

    @Test
    void isVerifierIssuer_CompletelyDifferentUrl_ReturnsFalse() {
        when(appProperties.verifierUrl()).thenReturn("https://altia.127.0.0.1.nip.io:4444");

        assertFalse(appConfig.isVerifierIssuer("https://evil.example.com"));
    }
}
