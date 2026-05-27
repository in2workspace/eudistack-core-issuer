package es.in2.issuer.backend.dome.infrastructure.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "issuer.dome.key-migration")
public record KeyMigrationProperties(
        @DefaultValue("false") boolean planAEnabled,
        @DefaultValue("false") boolean planBEnabled,
        @DefaultValue("alias/dome/signing") String kmsAlias,
        @DefaultValue("alias/dome/signing-v2") String kmsAliasV2,
        @DefaultValue("") String legacyKeyId,
        @DefaultValue("") String legacyPublicKeyHex,
        @DefaultValue("60") int cacheJwksTtlSeconds,
        @DefaultValue("http://localhost:8200") String vaultEndpoint,
        @DefaultValue("dome") String tenantDomain
) {
}

