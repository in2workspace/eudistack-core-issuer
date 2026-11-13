package es.in2.issuer.backend.shared.domain.spi;

import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

/**
 * Request counters of the volume limits, one per requester and bucket of time, shared by every issuer instance
 * (EUD-269). Scoped to the tenant of the request, like every other store of the issuer.
 */
public interface VolumeCounterStore {

    /**
     * Counts one more request in {@code currentBucket} of {@code counterKey}, atomically across instances, and
     * reads the other buckets of the window.
     *
     * @param oldestBucket start of the oldest bucket to read
     * @return requests per bucket start, from {@code oldestBucket} to {@code currentBucket}, this request included
     */
    Mono<Map<Instant, Long>> increment(String counterKey, Instant currentBucket, Instant oldestBucket);

    /** Takes back one request of {@code bucket}: a rejected request does not use up the limit. */
    Mono<Void> undo(String counterKey, Instant bucket);

    /** Deletes the buckets that started before {@code before}; returns how many. */
    Mono<Long> purgeBefore(Instant before);
}
