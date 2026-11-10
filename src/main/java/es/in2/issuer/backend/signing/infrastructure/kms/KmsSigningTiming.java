package es.in2.issuer.backend.signing.infrastructure.kms;

import java.time.Duration;

/**
 * Timeouts and retries of a KMS {@code Sign}. They are fixed, as in the QTSP flow: {@link #DEFAULT} holds the
 * values of the EUD-251 PRD (NFR-2: 10 s per attempt; NFR-3: 3 retries with growing waits) and of its
 * design (200 ms initial backoff, 45 s deadline). Other values are only for tests.
 *
 * <p>{@code callTimeout} bounds each attempt, {@code maxRetries} the retries after the first attempt
 * and {@code deadline} a whole {@code Sign} with its retries. With the defaults the deadline is not
 * reached before the last retry ends; it only stops a call that would otherwise last longer.
 */
public record KmsSigningTiming(
        Duration callTimeout,
        int maxRetries,
        Duration initialBackoff,
        Duration maxBackoff,
        Duration deadline
) {
    public static final KmsSigningTiming DEFAULT = new KmsSigningTiming(
            Duration.ofSeconds(10), 3, Duration.ofMillis(200), Duration.ofSeconds(5), Duration.ofSeconds(45));

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
