package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.IssuanceDetail;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import reactor.core.publisher.Mono;

import java.util.UUID;

/** The query use case of the issuance processes (EUD-255). */
public interface IssuanceQueryService {

    /**
     * A page of the processes within the scope of the decision (FR-03, FR-04, FR-10): the caller's
     * organization, the whole tenant, or every tenant from the platform tenant.
     * Fails with {@code InvalidQueryException} when the cursor does not belong to these filters or
     * the tenant filter is not accepted for this caller.
     */
    Mono<IssuanceList> list(AuthorizationDecision decision, IssuanceQuery query);

    /**
     * One process within the scope of the decision, with its attestation data (FR-06, FR-10). Fails with
     * {@code IssuanceNotFoundException} both when it does not exist and when it is outside the scope.
     */
    Mono<IssuanceDetail> detail(AuthorizationDecision decision, UUID issuanceId);
}
