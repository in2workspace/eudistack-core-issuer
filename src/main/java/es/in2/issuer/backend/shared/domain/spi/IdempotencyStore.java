package es.in2.issuer.backend.shared.domain.spi;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Idempotency keys, shared by every issuer instance and kept across restarts (EUD-269, FR-08 of
 * EUD-254). Scoped to the tenant of the request. {@link #claim} must be atomic, so two instances that
 * receive the same key at once never both process it.
 */
public interface IdempotencyStore {

    /**
     * Takes the key for a request, or says why it cannot:
     * <ul>
     *   <li>{@link IdempotencyClaim.Acquired} when the key is new, expired, or held by a request with the
     *       same body whose lease ended;</li>
     *   <li>{@link IdempotencyClaim.Replay} when it has a successful response for the same body;</li>
     *   <li>{@link IdempotencyClaim.InProgress} when a request with the same body holds it;</li>
     *   <li>{@link IdempotencyClaim.KeyReused} when it was used with another body.</li>
     * </ul>
     *
     * @param scopeKey    HMAC of the key within its requester (never the raw key of another requester)
     * @param requestHash HMAC of the canonical request body
     * @param ownerId     identifies this request as the holder of the key
     * @param lockedUntil end of the lease of this request
     * @param expiresAt   end of the retention of the key
     */
    Mono<IdempotencyClaim> claim(String scopeKey, String requestHash, String ownerId,
                                 Instant now, Instant lockedUntil, Instant expiresAt);

    /**
     * Looks a key up without taking it, for a key kept with the previous secret while it is rotated: what
     * {@link #claim} would answer for it, or empty when the key is not there, has expired or is held by a
     * request with the same body whose lease ended (then the key is claimed with the current secret).
     */
    Mono<IdempotencyClaim> find(String scopeKey, String requestHash, Instant now);

    /** Keeps the successful response of the request that holds the key. A no-op if it no longer holds it. */
    Mono<Void> complete(String scopeKey, String ownerId, StoredResponse response);

    /** Frees the key of a request that failed, so a retry is processed again. A no-op if it no longer holds it. */
    Mono<Void> release(String scopeKey, String ownerId);

    /** Moves the end of the lease of the request that holds the key. A no-op if it no longer holds it. */
    Mono<Void> renew(String scopeKey, String ownerId, Instant lockedUntil);

    /** Deletes the keys whose retention ended; returns how many. */
    Mono<Long> purgeExpired(Instant now);
}
