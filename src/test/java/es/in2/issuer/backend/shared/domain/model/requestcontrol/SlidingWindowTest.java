package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SlidingWindowTest {

    private static final SlidingWindow MINUTE = new SlidingWindow(Duration.ofMinutes(1));
    private static final Instant MINUTE_START = Instant.parse("2026-11-10T10:00:00Z");
    /** 30.5 s into the minute: the current bucket started at 30 s. */
    private static final Instant NOW = MINUTE_START.plusMillis(30_500);

    private static Instant second(long offset) {
        return MINUTE_START.plusSeconds(offset);
    }

    @Test
    void buckets_areOneSecond_andTheWindowReadsFromTheBucketLeavingIt() {
        assertThat(MINUTE.bucket()).isEqualTo(Duration.ofSeconds(1));
        assertThat(MINUTE.currentBucket(NOW)).isEqualTo(second(30));
        assertThat(MINUTE.oldestCountedBucket(NOW)).isEqualTo(second(-30));
    }

    @Test
    void decide_theRequestThatReachesTheLimit_isAllowed() {
        VolumeLimitDecision decision = MINUTE.decide(Map.of(second(30), 300L), 300, NOW);

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.retryAfterSeconds()).isZero();
    }

    @Test
    void decide_theRequestAfterTheLimit_waitsUntilItsBucketLeavesTheWindow() {
        VolumeLimitDecision decision = MINUTE.decide(Map.of(second(30), 301L), 300, NOW);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.limit()).isEqualTo(300);
        // The 300 of [30 s, 31 s) leave the window during [90 s, 91 s); at 90.001 s only 299 remain: 59.5 s from now.
        assertThat(decision.retryAfterSeconds()).isEqualTo(60);
    }

    @Test
    void decide_aBurstThatCrossesTheMinute_isCountedWhole() {
        // 150 at -10 s and 150 at 20 s: 300 in the last minute, the next one is the 301st (AC-08).
        Map<Instant, Long> buckets = Map.of(second(-10), 150L, second(20), 150L, second(30), 1L);

        VolumeLimitDecision decision = MINUTE.decide(buckets, 300, NOW);

        assertThat(decision.allowed()).isFalse();
        // The bucket of -10 s leaves the window during [50 s, 51 s): at 50.001 s, 149 of it and 150 remain.
        assertThat(decision.retryAfterSeconds()).isEqualTo(20);
        assertThat(MINUTE.decide(Map.of(second(-10), 150L, second(20), 150L), 300, NOW).allowed()).isTrue();
    }

    @Test
    void decide_theWindowIsSixtySecondsNotSixtyOne_soASteadyFlowAtTheLimitIsNeverRejected() {
        // 5 per second (300 a minute) at 0.1, 0.3, 0.5, 0.7 and 0.9 of each second, for three minutes.
        Map<Instant, Long> buckets = new HashMap<>();
        int rejected = 0;
        for (int second = 0; second < 180; second++) {
            for (int i = 0; i < 5; i++) {
                Instant at = MINUTE_START.plusMillis(second * 1000L + 100 + i * 200L);
                Instant bucket = MINUTE.currentBucket(at);
                buckets.merge(bucket, 1L, Long::sum);
                if (!MINUTE.decide(buckets, 300, at).allowed()) {
                    rejected++;
                    buckets.merge(bucket, -1L, Long::sum);
                }
            }
        }

        assertThat(rejected).isZero();
    }

    @Test
    void decide_theOutgoingBucket_countsByThePartStillInsideTheWindow() {
        // At 30.5 s the bucket of -30 s is half inside the window (-29.5 s, 30.5 s].
        Map<Instant, Long> buckets = Map.of(second(-30), 100L, second(0), 250L, second(30), 1L);

        assertThat(MINUTE.decide(buckets, 301, NOW).allowed()).isTrue();
        assertThat(MINUTE.decide(buckets, 300, NOW).allowed()).isFalse();
    }

    @Test
    void decide_bucketsOlderThanTheWindow_doNotCount() {
        Map<Instant, Long> buckets = Map.of(second(-31), 500L, second(30), 1L);

        assertThat(MINUTE.decide(buckets, 1, NOW).allowed()).isTrue();
    }

    @Test
    void decide_retryAfterIsNeverZeroAndNeverBeyondTheWindow() {
        VolumeLimitDecision decision = MINUTE.decide(Map.of(second(30), 1_000L), 1, NOW.plusMillis(499));

        assertThat(decision.retryAfterSeconds()).isBetween(1L, 61L);
    }

    @Test
    void invalidWindowOrLimit_isRejected() {
        Duration tooShort = Duration.ofMillis(59);

        assertThatThrownBy(() -> new SlidingWindow(tooShort)).isInstanceOf(IllegalArgumentException.class);
        Map<Instant, Long> noBuckets = Map.of();

        assertThatThrownBy(() -> MINUTE.decide(noBuckets, 0, NOW)).isInstanceOf(IllegalArgumentException.class);
    }
}
