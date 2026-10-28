package es.in2.issuer.backend.shared.domain.policy.service;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.IssuanceAuthorization;
import es.in2.issuer.backend.shared.domain.policy.RecognizedCaller;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * The single decision point of the issuer actions (EUD-253, FR-15). Every decision is taken from the
 * caller's powers, the request's tenant (from {@code X-Tenant}) and the organization stored with the
 * resource, following the action matrix in force; it never reads the tenant configuration, the
 * credential profile or the attestation content, and it is the same for persons and systems (FR-08).
 * Every decision, permitted or denied, leaves a trace (FR-13).
 */
public interface PowerAuthorizationService {

    /** Matrix action ids handled by the issuer today. */
    String ISSUE_OWN = "E1";
    String ISSUE_ON_BEHALF = "E2";
    String ISSUE_PRODUCT_CERTIFICATION = "E6";
    String WITHDRAW = "E7";
    String QUERY = "C1";
    String QUERY_FROM_SYSTEM = "C2";
    String REVOKE = "R1";
    String ARCHIVE = "R2";

    /** The actions the issuer decides: a matrix without a rule for one of them is rejected. */
    List<String> ACTIONS_IN_USE = List.of(ISSUE_OWN, ISSUE_ON_BEHALF, ISSUE_PRODUCT_CERTIFICATION, WITHDRAW,
            QUERY, QUERY_FROM_SYSTEM, REVOKE, ARCHIVE);

    /**
     * Resolves the user type of the caller in the request's tenant, for the callers that need the
     * role without deciding an action ({@code GET /me}, the catalog). The token must have been issued
     * for that tenant (FR-02): otherwise it fails as {@code TenantMismatchException}, traced.
     */
    Mono<RecognizedCaller> recognize(Caller caller);

    /**
     * Decides an action on a resource (or on no resource when {@code resourceOrganization} is null:
     * a listing, whose results the decision's scope then narrows).
     *
     * <p>A resource outside the caller's scope fails as {@code IssuanceNotFoundException}, so its
     * existence is not disclosed; the trace keeps the real reason.
     */
    Mono<AuthorizationDecision> authorize(String actionId, Caller caller, String resourceOrganization, String resourceId);

    /** {@link #authorize(String, Caller, String, String)} for the caller of the current request. */
    Mono<AuthorizationDecision> authorize(String actionId, String resourceOrganization, String resourceId);

    /**
     * Decides a query (list, search or detail) of the current request's caller: {@code C2} when it is a
     * system -- it authenticated with a LEAR machine attestation -- and {@code C1} for a person, each with
     * its own rule and trace.
     */
    Mono<AuthorizationDecision> authorizeQuery(String resourceOrganization, String resourceId);

    /**
     * Decides an issuance of the current request's caller: E1 or E6 for the type, E2 when the
     * requested organization is not the caller's, and the grant rules (E3, E4, E5, E9) for every
     * power the new attestation carries in {@code payload.power} (FR-10).
     *
     * @param processId             correlates the decision's trace with the issued attestation's
     * @param credentialType        type of the attestation to issue ({@code credential_definition.type})
     * @param requestedOrganization organization indicated in the request, or null for the caller's
     */
    Mono<IssuanceAuthorization> authorizeIssuance(String processId, String credentialConfigurationId, String credentialType,
                                                  String requestedOrganization, JsonNode payload);
}
