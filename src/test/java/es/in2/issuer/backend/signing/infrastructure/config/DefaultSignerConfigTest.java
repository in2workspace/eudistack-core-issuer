package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.infrastructure.properties.DefaultSignerProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DefaultSignerConfigTest {

    @Mock
    private DefaultSignerProperties defaultSignerProperties;

    @InjectMocks
    private DefaultSignerConfig defaultSignerConfig;

    @Test
    void testGetCommonName() {
        when(defaultSignerProperties.commonName()).thenReturn("CommonName");
        assertEquals("CommonName", defaultSignerConfig.getCommonName());
    }

    @Test
    void testGetCountry() {
        when(defaultSignerProperties.country()).thenReturn("Country");
        assertEquals("Country", defaultSignerConfig.getCountry());
    }

    @Test
    void testGetEmail() {
        when(defaultSignerProperties.email()).thenReturn("email");
        assertEquals("email", defaultSignerConfig.getEmail());
    }

    @Test
    void testGetOrganizationIdentifier() {
        when(defaultSignerProperties.organizationIdentifier()).thenReturn("OrgId");
        assertEquals("OrgId", defaultSignerConfig.getOrganizationIdentifier());
    }

    @Test
    void testGetOrganization() {
        when(defaultSignerProperties.organization()).thenReturn("Organization");
        assertEquals("Organization", defaultSignerConfig.getOrganization());
    }

    @Test
    void testGetSerialNumber() {
        when(defaultSignerProperties.serialNumber()).thenReturn("SerialNumber");
        assertEquals("SerialNumber", defaultSignerConfig.getSerialNumber());
    }
}
