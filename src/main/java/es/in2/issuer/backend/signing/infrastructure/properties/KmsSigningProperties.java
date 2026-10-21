package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * KMS own-key signing settings (EUD-289). Disabled by default; {@code endpoint} is only for
 * emulators such as LocalStack.
 */
@ConfigurationProperties(prefix = "issuer.signing.kms")
public record KmsSigningProperties(
        @DefaultValue("false") boolean enabled,
        String region,
        URI endpoint,
        @DefaultValue("10s") Duration callTimeout,
        @DefaultValue("3") int maxRetries,
        @DefaultValue("1s") Duration initialBackoff,
        @DefaultValue("5s") Duration maxBackoff
) {
    public KmsSigningProperties {
        Objects.requireNonNull(callTimeout, "issuer.signing.kms.call-timeout is required");
        Objects.requireNonNull(initialBackoff, "issuer.signing.kms.initial-backoff is required");
        Objects.requireNonNull(maxBackoff, "issuer.signing.kms.max-backoff is required");
        if (callTimeout.isZero() || callTimeout.isNegative()) {
            throw new IllegalArgumentException("issuer.signing.kms.call-timeout must be positive");
        }
        if (maxRetries < 0) {
            throw new IllegalArgumentException("issuer.signing.kms.max-retries must not be negative");
        }
        if (enabled && (region == null || region.isBlank())) {
            throw new IllegalArgumentException(
                    "issuer.signing.kms.region is required when issuer.signing.kms.enabled=true");
        }
    }
}
