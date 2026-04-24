package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.properties.AppProperties;
import es.in2.issuer.backend.shared.infrastructure.config.properties.IssuerIdentityProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    void getSysTenant_returnsConfiguredValue() {
        when(appProperties.sysTenant()).thenReturn("sys-tenant");
        assertEquals("sys-tenant", appConfig.getSysTenant());
    }

    @Test
    void getIssuerInternalUrl_returnsConfiguredValue() {
        when(appProperties.internalUrl()).thenReturn("http://issuer-core:8080/issuer");
        assertEquals("http://issuer-core:8080/issuer", appConfig.getIssuerInternalUrl());
    }

    @Test
    void getVerifierInternalUrl_returnsConfiguredValue() {
        when(appProperties.verifierInternalUrl()).thenReturn("http://verifier-core:8080/verifier");
        assertEquals("http://verifier-core:8080/verifier", appConfig.getVerifierInternalUrl());
    }

    @Test
    void getDefaultLang_returnsConfiguredValue() {
        when(appProperties.defaultLang()).thenReturn("es");
        assertEquals("es", appConfig.getDefaultLang());
    }
}
