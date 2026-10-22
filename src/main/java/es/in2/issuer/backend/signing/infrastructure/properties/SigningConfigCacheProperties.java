package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.Objects;

/**
 * Cache of the per-tenant active signing configuration. The default keeps the 5 minutes the
 * EUD-251 design (AD-5) retains.
 */
@ConfigurationProperties(prefix = "issuer.signing")
public record SigningConfigCacheProperties(
        @DefaultValue("5m") Duration configCacheTtl
) {
    public SigningConfigCacheProperties {
        Objects.requireNonNull(configCacheTtl, "issuer.signing.config-cache-ttl is required");
        if (configCacheTtl.isZero() || configCacheTtl.isNegative()) {
            throw new IllegalArgumentException("issuer.signing.config-cache-ttl must be positive");
        }
    }
}
