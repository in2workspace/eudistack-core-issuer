package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.spi.VolumeCounterStore;
import lombok.RequiredArgsConstructor;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * R2DBC adapter of {@link VolumeCounterStore} on {@code api_volume_counter} (V19). Tenant-scoped via
 * {@code search_path}: the tenant must be in the Reactor context before subscribing.
 *
 * <p>One statement per request: an {@code INSERT ... ON CONFLICT DO UPDATE} of the current bucket, atomic
 * across instances, whose {@code RETURNING} gives its count after this request, and the other buckets of the
 * window, which no longer change.
 */
@Repository
@RequiredArgsConstructor
public class R2dbcVolumeCounterStore implements VolumeCounterStore {

    private static final String INCREMENT_SQL = """
            WITH current_bucket AS (
                INSERT INTO api_volume_counter (counter_key, window_start, request_count)
                VALUES (:counterKey, :currentBucket, 1)
                ON CONFLICT (counter_key, window_start)
                DO UPDATE SET request_count = api_volume_counter.request_count + 1
                RETURNING window_start, request_count
            )
            SELECT window_start, request_count FROM current_bucket
            UNION ALL
            SELECT window_start, request_count FROM api_volume_counter
            WHERE counter_key = :counterKey AND window_start >= :oldestBucket AND window_start < :currentBucket
            """;

    private final DatabaseClient databaseClient;

    @Override
    public Mono<Map<Instant, Long>> increment(String counterKey, Instant currentBucket, Instant oldestBucket) {
        return databaseClient.sql(INCREMENT_SQL)
                .bind("counterKey", counterKey)
                .bind("currentBucket", currentBucket)
                .bind("oldestBucket", oldestBucket)
                .map((row, metadata) -> Map.entry(row.get("window_start", Instant.class),
                        toLong(row.get("request_count", Number.class))))
                .all()
                .collect(HashMap<Instant, Long>::new, (buckets, bucket) -> buckets.merge(bucket.getKey(),
                        bucket.getValue(), Long::sum))
                .map(Map::copyOf);
    }

    @Override
    public Mono<Long> purgeBefore(Instant before) {
        return databaseClient.sql("DELETE FROM api_volume_counter WHERE window_start < :before")
                .bind("before", before)
                .fetch()
                .rowsUpdated();
    }

    private static long toLong(Number value) {
        return value != null ? value.longValue() : 0L;
    }
}
