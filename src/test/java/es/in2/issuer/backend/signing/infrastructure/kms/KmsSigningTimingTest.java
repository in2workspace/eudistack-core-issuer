package es.in2.issuer.backend.signing.infrastructure.kms;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class KmsSigningTimingTest {

    /** EUD-251 PRD NFR-2 and NFR-3, and the backoff and deadline of its design. */
    @Test
    void defaults_areThoseOfThePrdAndTheDesign() {
        KmsSigningTiming timing = KmsSigningTiming.DEFAULT;

        assertThat(timing.callTimeout()).isEqualTo(Duration.ofSeconds(10));
        assertThat(timing.maxRetries()).isEqualTo(3);
        assertThat(timing.initialBackoff()).isEqualTo(Duration.ofMillis(200));
        assertThat(timing.maxBackoff()).isEqualTo(Duration.ofSeconds(5));
        assertThat(timing.deadline()).isEqualTo(Duration.ofSeconds(45));
    }

    @Test
    void worstCaseSigningDuration_neverExceedsTheDeadline() {
        Duration callTimeout = Duration.ofSeconds(10);
        Duration initialBackoff = Duration.ofMillis(200);
        Duration maxBackoff = Duration.ofSeconds(5);

        // 4 attempts of 10 s and 3 waits of at most 5 s would be 55 s: the deadline caps it.
        assertThat(new KmsSigningTiming(callTimeout, 3, initialBackoff, maxBackoff, Duration.ofSeconds(45))
                .worstCaseSigningDuration()).isEqualTo(Duration.ofSeconds(45));
        assertThat(new KmsSigningTiming(callTimeout, 3, initialBackoff, maxBackoff, Duration.ofSeconds(60))
                .worstCaseSigningDuration()).isEqualTo(Duration.ofSeconds(55));
    }
}
