package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Startup signing self-test of own-key tenants (EUD-289 AC-18). {@code enabled} is the kill switch;
 * {@code tenantTimeout} bounds the probe of each tenant so a slow KMS can never hold anything up.
 * Unset, it is derived from the KMS call timeout and retries (see {@code OwnKeySigningSelfTest}).
 */
@ConfigurationProperties(prefix = "issuer.signing.startup-self-test")
public record SigningSelfTestProperties(
        @DefaultValue("true") boolean enabled,
        Duration tenantTimeout
) {
    public SigningSelfTestProperties {
        if (tenantTimeout != null && (tenantTimeout.isZero() || tenantTimeout.isNegative())) {
            throw new IllegalArgumentException("issuer.signing.startup-self-test.tenant-timeout must be positive");
        }
    }
}
