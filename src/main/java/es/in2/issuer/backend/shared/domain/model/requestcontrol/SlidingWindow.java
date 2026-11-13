package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

/**
 * The window of a volume limit (EUD-269): the requests of the last {@code length}, counted in buckets of a
 * sixtieth of it (one second for the minute of the management APIs). The total is the sum of every bucket that
 * may hold a request of the window, so it never undercounts a burst that crosses the edge of a minute ("300
 * in the last minute", AC-08 of EUD-254); at most it counts one bucket more, which makes it slightly strict,
 * never lax. The counters are shared by every instance.
 *
 * @param length how long the window is (one minute for every limit of the management APIs)
 */
public record SlidingWindow(Duration length) {

    private static final int BUCKETS = 60;

    public SlidingWindow {
        Objects.requireNonNull(length, "length");
        if (length.toMillis() < BUCKETS) {
            throw new IllegalArgumentException("The window must be at least " + BUCKETS + " ms");
        }
    }

    /** How long one bucket is. */
    public Duration bucket() {
        return Duration.ofMillis(length.toMillis() / BUCKETS);
    }

    /** Start of the bucket {@code now} falls in. */
    public Instant currentBucket(Instant now) {
        long bucket = bucket().toMillis();
        return Instant.ofEpochMilli(Math.floorDiv(now.toEpochMilli(), bucket) * bucket);
    }

    /**
     * Start of the oldest bucket that may still hold a request of the last {@code length}: the buckets from it
     * to the current one are counted (one more than fit in the window, so the count is never short).
     */
    public Instant oldestCountedBucket(Instant now) {
        return currentBucket(now).minus(length);
    }

    /**
     * Decides a request already counted in its bucket.
     *
     * @param buckets requests per bucket start, for the buckets of the window (this request included)
     * @param limit   requests allowed in the window
     */
    public VolumeLimitDecision decide(Map<Instant, Long> buckets, int limit, Instant now) {
        if (limit < 1) {
            throw new IllegalArgumentException("The limit must be at least 1");
        }
        Instant oldest = oldestCountedBucket(now);
        NavigableMap<Instant, Long> counted = new TreeMap<>();
        buckets.forEach((start, count) -> {
            if (!start.isBefore(oldest) && count != null && count > 0) {
                counted.put(start, count);
            }
        });
        long total = counted.values().stream().mapToLong(Long::longValue).sum();
        if (total <= limit) {
            return VolumeLimitDecision.allowed(limit);
        }
        return VolumeLimitDecision.rejected(limit, toSeconds(waitMillis(counted, total, limit, now)));
    }

    /**
     * Until enough of the oldest buckets leave the window for one more request to fit. The rejected request is
     * taken back from its bucket, so one more fits once what remains of {@code total} (which still includes it)
     * is within the limit. A bucket stops being counted once it ended {@code length} ago.
     */
    private long waitMillis(NavigableMap<Instant, Long> counted, long total, int limit, Instant now) {
        long remaining = total;
        for (Map.Entry<Instant, Long> bucket : counted.entrySet()) {
            remaining -= bucket.getValue();
            if (remaining <= limit) {
                return bucket.getKey().plus(bucket()).plus(length).toEpochMilli() - now.toEpochMilli();
            }
        }
        return length.toMillis() + bucket().toMillis();
    }

    private static long toSeconds(long millis) {
        return Math.max(1, Math.ceilDiv(millis, 1000));
    }
}
