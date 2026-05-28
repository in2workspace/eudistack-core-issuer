package es.in2.issuer.backend.dome.infrastructure.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "issuer.dome.key-migration")
public record KeyMigrationProperties(
        @DefaultValue("false") boolean planAEnabled,
        @DefaultValue("") String legacyKeyId,
        @DefaultValue("http://localhost:8200") String vaultEndpoint,
        @DefaultValue("dome") String tenantDomain
) {
}

