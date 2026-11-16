package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import es.in2.issuer.backend.shared.domain.spi.IdempotencyStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * R2DBC adapter of {@link IdempotencyStore} on {@code api_idempotency_record} (V19). Tenant-scoped via
 * {@code search_path}: the tenant must be in the Reactor context before subscribing.
 *
 * <p>A claim is one {@code INSERT ... ON CONFLICT DO UPDATE ... WHERE}: it takes a new key, an expired one,
 * or one held by a request with the same body whose lease ended, atomically across instances. When it takes
 * nothing, the row that stopped it says why. A row that disappears or expires between the two statements (a
 * concurrent release or purge) is claimed again, a bounded number of times.
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public class R2dbcIdempotencyStore implements IdempotencyStore {

    static final String STATE_COMPLETED = "COMPLETED";
    private static final String SCOPE_KEY = "scopeKey";
    private static final String OWNER_ID = "ownerId";
    private static final int MAX_CLAIM_ATTEMPTS = 3;

    private static final String CLAIM_SQL = """
            INSERT INTO api_idempotency_record
                (scope_key, request_hash, state, owner_id, locked_until, expires_at, created_at)
            VALUES (:scopeKey, :requestHash, 'IN_PROGRESS', :ownerId, :lockedUntil, :expiresAt, :now)
            ON CONFLICT (scope_key) DO UPDATE SET
                request_hash = EXCLUDED.request_hash,
                state = 'IN_PROGRESS',
                owner_id = EXCLUDED.owner_id,
                locked_until = EXCLUDED.locked_until,
                expires_at = EXCLUDED.expires_at,
                created_at = EXCLUDED.created_at,
                response_status = NULL,
                response_content_type = NULL,
                response_location = NULL,
                response_body = NULL
            WHERE api_idempotency_record.expires_at <= EXCLUDED.created_at
               OR (api_idempotency_record.state = 'IN_PROGRESS'
                   AND api_idempotency_record.locked_until <= EXCLUDED.created_at
                   AND api_idempotency_record.request_hash = EXCLUDED.request_hash)
            RETURNING owner_id
            """;

    private static final String READ_SQL = """
            SELECT request_hash, state, locked_until, expires_at,
                   response_status, response_content_type, response_location, response_body
            FROM api_idempotency_record WHERE scope_key = :scopeKey
            """;

    private static final String COMPLETE_SQL = """
            UPDATE api_idempotency_record
            SET state = 'COMPLETED', response_status = :status, response_content_type = :contentType,
                response_location = :location, response_body = :body
            WHERE scope_key = :scopeKey AND owner_id = :ownerId AND state = 'IN_PROGRESS'
            """;

    private static final String RENEW_SQL = """
            UPDATE api_idempotency_record SET locked_until = :lockedUntil
            WHERE scope_key = :scopeKey AND owner_id = :ownerId AND state = 'IN_PROGRESS'
            """;

    private static final String RELEASE_SQL = """
            DELETE FROM api_idempotency_record
            WHERE scope_key = :scopeKey AND owner_id = :ownerId AND state = 'IN_PROGRESS'
            """;

    private final DatabaseClient databaseClient;

    /** The row that stopped a claim; {@code response} only when it is completed. */
    private record ExistingRecord(String requestHash, String state, Instant lockedUntil, Instant expiresAt,
                                  StoredResponse response) { }

    @Override
    public Mono<IdempotencyClaim> claim(String scopeKey, String requestHash, String ownerId,
                                        Instant now, Instant lockedUntil, Instant expiresAt) {
        return claim(scopeKey, requestHash, ownerId, now, lockedUntil, expiresAt, 1);
    }

    private Mono<IdempotencyClaim> claim(String scopeKey, String requestHash, String ownerId,
                                         Instant now, Instant lockedUntil, Instant expiresAt, int attempt) {
        return databaseClient.sql(CLAIM_SQL)
                .bind(SCOPE_KEY, scopeKey)
                .bind("requestHash", requestHash)
                .bind(OWNER_ID, UUID.fromString(ownerId))
                .bind("lockedUntil", lockedUntil)
                .bind("expiresAt", expiresAt)
                .bind("now", now)
                .map((row, metadata) -> row.get("owner_id", UUID.class))
                .one()
                .<IdempotencyClaim>map(owner -> new IdempotencyClaim.Acquired(scopeKey, owner.toString()))
                .switchIfEmpty(Mono.defer(() -> read(scopeKey)
                        .flatMap(existing -> resolve(existing, requestHash, now))
                        // Gone or expired between the two statements: the key is free again.
                        .switchIfEmpty(Mono.defer(() -> attempt < MAX_CLAIM_ATTEMPTS
                                ? claim(scopeKey, requestHash, ownerId, now, lockedUntil, expiresAt, attempt + 1)
                                : Mono.just(new IdempotencyClaim.InProgress())))));
    }

    @Override
    public Mono<IdempotencyClaim> find(String scopeKey, String requestHash, Instant now) {
        return read(scopeKey).flatMap(existing -> resolve(existing, requestHash, now));
    }

    /** Why the claim took nothing; empty when the row no longer stops it (the claim is retried). */
    private static Mono<IdempotencyClaim> resolve(ExistingRecord existing, String requestHash, Instant now) {
        if (!existing.expiresAt().isAfter(now)) {
            return Mono.empty();
        }
        if (!existing.requestHash().equals(requestHash)) {
            return Mono.just(new IdempotencyClaim.KeyReused());
        }
        if (STATE_COMPLETED.equals(existing.state())) {
            return Mono.just(new IdempotencyClaim.Replay(existing.response()));
        }
        // An expired lease with the same body was taken over by a concurrent retry: retry to see its outcome.
        return existing.lockedUntil().isAfter(now) ? Mono.just(new IdempotencyClaim.InProgress()) : Mono.empty();
    }

    private Mono<ExistingRecord> read(String scopeKey) {
        return databaseClient.sql(READ_SQL)
                .bind(SCOPE_KEY, scopeKey)
                .map((row, metadata) -> {
                    String state = row.get("state", String.class);
                    Integer status = row.get("response_status", Integer.class);
                    StoredResponse response = STATE_COMPLETED.equals(state) && status != null
                            ? new StoredResponse(status, row.get("response_content_type", String.class),
                                    row.get("response_location", String.class), row.get("response_body", byte[].class))
                            : null;
                    return new ExistingRecord(row.get("request_hash", String.class), state,
                            row.get("locked_until", Instant.class), row.get("expires_at", Instant.class), response);
                })
                .one();
    }

    @Override
    public Mono<Void> complete(String scopeKey, String ownerId, StoredResponse response) {
        DatabaseClient.GenericExecuteSpec spec = databaseClient.sql(COMPLETE_SQL)
                .bind(SCOPE_KEY, scopeKey)
                .bind(OWNER_ID, UUID.fromString(ownerId))
                .bind("status", response.status())
                .bind("body", response.body());
        spec = response.contentType() != null
                ? spec.bind("contentType", response.contentType())
                : spec.bindNull("contentType", String.class);
        spec = response.location() != null
                ? spec.bind("location", response.location())
                : spec.bindNull("location", String.class);
        return spec.fetch().rowsUpdated()
                .doOnNext(rows -> {
                    if (rows == 0) {
                        log.warn("Idempotency key no longer held by its request; its response is not kept");
                    }
                })
                .then();
    }

    @Override
    public Mono<Void> release(String scopeKey, String ownerId) {
        return databaseClient.sql(RELEASE_SQL)
                .bind(SCOPE_KEY, scopeKey)
                .bind(OWNER_ID, UUID.fromString(ownerId))
                .fetch()
                .rowsUpdated()
                .then();
    }

    @Override
    public Mono<Void> renew(String scopeKey, String ownerId, Instant lockedUntil) {
        return databaseClient.sql(RENEW_SQL)
                .bind(SCOPE_KEY, scopeKey)
                .bind(OWNER_ID, UUID.fromString(ownerId))
                .bind("lockedUntil", lockedUntil)
                .fetch()
                .rowsUpdated()
                .then();
    }

    @Override
    public Mono<Long> purgeExpired(Instant now) {
        return databaseClient.sql("DELETE FROM api_idempotency_record WHERE expires_at <= :now")
                .bind("now", now)
                .fetch()
                .rowsUpdated();
    }
}
