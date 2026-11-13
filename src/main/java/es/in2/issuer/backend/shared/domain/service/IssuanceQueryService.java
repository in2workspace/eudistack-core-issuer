package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import reactor.core.publisher.Mono;

/** The query use case of the issuance processes (EUD-255). */
public interface IssuanceQueryService {

    /**
     * A page of the processes within the scope of the decision (FR-03, FR-04, FR-10): the caller's
     * organization, the whole tenant, or every tenant from the platform tenant.
     * Fails with {@code InvalidQueryException} when the cursor does not belong to these filters or
     * the tenant filter is not accepted for this caller.
     */
    Mono<IssuanceList> list(AuthorizationDecision decision, IssuanceQuery query);
}
