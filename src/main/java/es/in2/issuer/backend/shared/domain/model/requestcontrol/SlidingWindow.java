package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

/**
 * The window of a volume limit (EUD-269): the requests of the last {@code length}, counted in buckets of a
 * sixtieth of it (one second for the minute of the management APIs). The total is the current bucket, the 59
 * before it, and the requests of the bucket that is leaving the window in proportion to the part of it still
 * inside (rounded down): a window of exactly {@code length} ("300 per minute", FR-09 and AC-08 of EUD-254), so a
 * client that sends 300 a minute at a steady rate is never rejected. Inside the outgoing bucket the requests are
 * taken as spread over it, so a burst at its very start may be counted short while it leaves (at most the
 * requests of that one bucket, during that one bucket). The counters are shared by every instance.
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
     * Start of the oldest bucket still counted: the one leaving the window, of which only the part still inside
     * it counts. The buckets from it to the current one are read.
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
        if (total(counted, now) <= limit) {
            return VolumeLimitDecision.allowed(limit);
        }
        // The rejected request is taken back from its bucket: the wait is until one more fits without it.
        counted.computeIfPresent(currentBucket(now), (start, count) -> count > 1 ? count - 1 : null);
        return VolumeLimitDecision.rejected(limit, toSeconds(waitMillis(counted, limit, now)));
    }

    /**
     * The requests in the window ending at {@code at}: the buckets after the outgoing one whole, and the outgoing
     * one in proportion to the part of it still inside the window, rounded down.
     */
    private long total(NavigableMap<Instant, Long> counted, Instant at) {
        long bucketMillis = bucket().toMillis();
        Instant outgoing = oldestCountedBucket(at);
        long insideMillis = currentBucket(at).toEpochMilli() + bucketMillis - at.toEpochMilli();
        long total = 0;
        for (Map.Entry<Instant, Long> bucket : counted.entrySet()) {
            if (bucket.getKey().isBefore(outgoing)) {
                continue;
            }
            total += bucket.getKey().equals(outgoing)
                    ? Math.floorDiv(bucket.getValue() * insideMillis, bucketMillis)
                    : bucket.getValue();
        }
        return total;
    }

    /**
     * Until one more request fits, without new ones. The count only goes down as time passes: each bucket, oldest
     * first, leaves the window during the bucket that starts {@code length} after it. For the first bucket whose
     * newer ones leave room, the wait is the moment enough of it has left.
     */
    private long waitMillis(NavigableMap<Instant, Long> counted, int limit, Instant now) {
        long bucketMillis = bucket().toMillis();
        long room = limit - 1L;
        long newer = counted.values().stream().mapToLong(Long::longValue).sum();
        for (Map.Entry<Instant, Long> bucket : counted.entrySet()) {
            long count = bucket.getValue();
            newer -= count;
            if (newer > room) {
                continue;
            }
            long leavingStarts = bucket.getKey().plus(length).toEpochMilli();
            // floor(count * (leavingStarts + bucket - t) / bucket) <= room - newer, solved for the first t.
            long fitsAt = leavingStarts + bucketMillis
                    - Math.floorDiv(bucketMillis * (room - newer + 1) - 1, count);
            return Math.max(fitsAt, Math.max(leavingStarts, now.toEpochMilli())) - now.toEpochMilli();
        }
        return length.toMillis();
    }

    private static long toSeconds(long millis) {
        return Math.max(1, Math.ceilDiv(millis, 1000));
    }
}
