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
     * A page of the processes within the scope of the decision (FR-03, FR-04, FR-05, FR-10, FR-11): the
     * caller's organization, the whole tenant, or every tenant from the platform tenant; a search by
     * identifier from the platform tenant needs the tenant it searches in.
     * Fails with {@code InvalidQueryException} when the cursor does not belong to these filters or
     * the tenant filter is missing or not accepted for this caller, with {@code UnknownIdentifierTypeException},
     * traced, when no catalogue entry of the tenant declares the identifier searched, with
     * {@code IssuanceQueryUnavailableException} when the processes, the catalogue or the tenant key cannot be
     * read, and with {@code AuditTrailUnavailableException}, returning nothing, when the page or the refusal
     * cannot be traced (AD-7).
     */
    Mono<IssuanceList> list(AuthorizationDecision decision, IssuanceQuery query);

    /**
     * One process within the caller's scope, with its attestation data (FR-06, FR-10). The permission is
     * decided here on the organization stored with the process, so that every refusal of the detail leaves
     * its trace (AD-7). Fails with {@code IssuanceNotFoundException} both when it does not exist and when it
     * is outside the scope, with the decision's error when the caller may not read processes, and with
     * {@code AuditTrailUnavailableException}, returning nothing, when the access or the refusal cannot be
     * traced.
     */
    Mono<IssuanceDetail> detail(UUID issuanceId);
}
