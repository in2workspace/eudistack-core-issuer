package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Idempotency of the issuance API (EUD-269, FR-08 of EUD-254): for 24 hours, the same key with the same
 * body gets the same successful response, whichever instance serves it and across restarts.
 */
public interface IdempotencyService {

    /**
     * Decides a request with an idempotency key. The key is scoped to its requester: two requesters never
     * share a key, whatever value they send.
     */
    Mono<IdempotencyClaim> claim(Requester requester, String idempotencyKey, byte[] requestBody);

    /** Keeps the successful response of a request that holds its key. */
    Mono<Void> complete(IdempotencyClaim.Acquired claim, StoredResponse response);

    /** Frees the key of a request that did not succeed: error responses are not kept. */
    Mono<Void> release(IdempotencyClaim.Acquired claim);

    /** Extends the lease of a request still in progress, so no retry takes its key over while it runs. */
    Mono<Void> renew(IdempotencyClaim.Acquired claim);

    /** How often a request in progress renews its lease. */
    Duration renewEvery();
}
