package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitDecision;
import reactor.core.publisher.Mono;

/**
 * Volume limits of the management APIs, per person and per organization for its systems, shared by
 * every issuer instance (EUD-269).
 */
public interface VolumeLimitService {

    /** Counts the request and decides whether it fits in the limit of its operation and requester. */
    Mono<VolumeLimitDecision> check(ApiOperation operation, Requester requester);
}
