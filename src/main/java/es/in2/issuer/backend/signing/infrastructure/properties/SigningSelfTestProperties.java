package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.Objects;

/**
 * Startup signing self-test of own-key tenants (EUD-289 AC-18). {@code enabled} is the kill switch;
 * {@code tenantTimeout} bounds the probe of each tenant so a slow KMS can never hold anything up.
 */
@ConfigurationProperties(prefix = "issuer.signing.startup-self-test")
public record SigningSelfTestProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("30s") Duration tenantTimeout
) {
    public SigningSelfTestProperties {
        Objects.requireNonNull(tenantTimeout, "issuer.signing.startup-self-test.tenant-timeout is required");
        if (tenantTimeout.isZero() || tenantTimeout.isNegative()) {
            throw new IllegalArgumentException("issuer.signing.startup-self-test.tenant-timeout must be positive");
        }
    }
}
