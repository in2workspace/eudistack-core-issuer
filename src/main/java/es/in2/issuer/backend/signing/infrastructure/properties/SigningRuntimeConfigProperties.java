package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "signing.runtime")
public record SigningRuntimeConfigProperties(
        boolean enabled,
        boolean controllerEnabled,
        String defaultProvider
) {
    public SigningRuntimeConfigProperties {
        if (defaultProvider == null || defaultProvider.isBlank()) {
            defaultProvider = "altia-mock-qtsp";
        }
    }
}
