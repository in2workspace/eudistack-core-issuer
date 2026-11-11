package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import java.time.Duration;
import java.util.Objects;

/**
 * How long an idempotency key lasts (EUD-269, FR-08 of EUD-254).
 *
 * @param retention how long a successful response is returned again for the same key and body (24 hours)
 * @param lease     how long a request in progress holds its key; after it, a retry with the same body may
 *                  take the key over, so an instance that stopped mid-request does not block it for the
 *                  whole retention
 */
public record IdempotencyPolicy(Duration retention, Duration lease) {

    public IdempotencyPolicy {
        Objects.requireNonNull(retention, "retention");
        Objects.requireNonNull(lease, "lease");
        if (retention.isNegative() || retention.isZero() || lease.isNegative() || lease.isZero()) {
            throw new IllegalArgumentException("The idempotency retention and lease must be positive");
        }
        if (lease.compareTo(retention) > 0) {
            throw new IllegalArgumentException("The idempotency lease cannot be longer than its retention");
        }
    }
}
