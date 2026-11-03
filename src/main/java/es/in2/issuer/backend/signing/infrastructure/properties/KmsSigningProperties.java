package es.in2.issuer.backend.signing.infrastructure.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * KMS own-key signing settings. Disabled by default; {@code endpoint} is only for
 * emulators such as LocalStack.
 *
 * <p>{@code callTimeout} bounds each attempt, {@code maxRetries} the retries after the first attempt
 * and {@code deadline} a whole {@code Sign} with its retries. With the defaults the deadline is not
 * reached before the last retry ends; it only stops a call that would otherwise last longer.
 */
@ConfigurationProperties(prefix = "issuer.signing.kms")
public record KmsSigningProperties(
        @DefaultValue("false") boolean enabled,
        String region,
        URI endpoint,
        @DefaultValue("10s") Duration callTimeout,
        @DefaultValue("3") int maxRetries,
        @DefaultValue("200ms") Duration initialBackoff,
        @DefaultValue("5s") Duration maxBackoff,
        @DefaultValue("45s") Duration deadline
) {
    public KmsSigningProperties {
        Objects.requireNonNull(callTimeout, "issuer.signing.kms.call-timeout is required");
        Objects.requireNonNull(initialBackoff, "issuer.signing.kms.initial-backoff is required");
        Objects.requireNonNull(maxBackoff, "issuer.signing.kms.max-backoff is required");
        Objects.requireNonNull(deadline, "issuer.signing.kms.deadline is required");
        if (callTimeout.isZero() || callTimeout.isNegative()) {
            throw new IllegalArgumentException("issuer.signing.kms.call-timeout must be positive");
        }
        if (deadline.compareTo(callTimeout) < 0) {
            throw new IllegalArgumentException(
                    "issuer.signing.kms.deadline must not be shorter than issuer.signing.kms.call-timeout");
        }
        if (maxRetries < 0) {
            throw new IllegalArgumentException("issuer.signing.kms.max-retries must not be negative");
        }
        if (enabled && (region == null || region.isBlank())) {
            throw new IllegalArgumentException(
                    "issuer.signing.kms.region is required when issuer.signing.kms.enabled=true");
        }
    }

    /**
     * Upper bound of one signing call with all its retries: every attempt times out and every wait
     * is the longest one ({@code maxBackoff} caps the backoff after jitter), but never more than
     * {@code deadline}, which cuts the call as a whole.
     */
    public Duration worstCaseSigningDuration() {
        Duration allAttempts = callTimeout.multipliedBy(maxRetries + 1L).plus(maxBackoff.multipliedBy(maxRetries));
        return allAttempts.compareTo(deadline) < 0 ? allAttempts : deadline;
    }
}
