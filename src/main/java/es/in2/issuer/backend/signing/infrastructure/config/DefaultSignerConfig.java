package es.in2.issuer.backend.signing.infrastructure.config;

import es.in2.issuer.backend.signing.domain.model.port.SignerConfig;
import es.in2.issuer.backend.signing.infrastructure.properties.DefaultSignerProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class DefaultSignerConfig implements SignerConfig {

    private final DefaultSignerProperties defaultSignerProperties;

    public String getCommonName() {
        return defaultSignerProperties.commonName();
    }

    public String getCountry() {
        return defaultSignerProperties.country();
    }

    public String getEmail() {
        return defaultSignerProperties.email();
    }

    public String getOrganizationIdentifier() {
        return defaultSignerProperties.organizationIdentifier();
    }

    public String getOrganization() {
        return defaultSignerProperties.organization();
    }

    public String getSerialNumber() {
        return defaultSignerProperties.serialNumber();
    }
}
