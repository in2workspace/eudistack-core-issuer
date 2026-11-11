package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.dtos.UpdateIssuanceStatusRequest;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceHttpResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.MalformedIssuanceIdException;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.shared.domain.util.IssuanceIds;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;

@Slf4j
@RestController
@RequestMapping(ISSUANCES_PATH)
@RequiredArgsConstructor
public class IssuanceController {

    /** Resource id traced for a path id that is not a process id. */
    static final String MALFORMED_ID = "<malformed>";

    private final IssuanceWorkflow issuanceWorkflow;
    private final IssuanceService issuanceService;
    private final PowerAuthorizationService powerAuthorizationService;
    private final RevocationWorkflow revocationWorkflow;
    private final UrlResolver urlResolver;
    private final IssuanceHttpEnvelopeMapper httpEnvelopeMapper;

    @PostMapping(
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<IssuanceHttpResponse>> createIssuance(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @Valid @RequestBody IssuanceRequest request,
            ServerWebExchange exchange) {
        String processId = UUID.randomUUID().toString();
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);
        // Direct delivery signs inside this request with the caller's bearer credential (EUD-168).
        // No second identity assertion is read: who may issue depends only on the caller's powers
        // (EUD-253, point 10 -- the X-Id-Token of product certifications is gone).
        return issuanceWorkflow.issueCredential(processId, request, authorizationHeader,
                        publicIssuerBaseUrl)
                .map(response -> toResponseEntity(response, publicIssuerBaseUrl));
    }

    /** C1/C2 (EUD-253): the decision's scope says whether the caller sees its organization or the whole tenant. */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<IssuanceList> getAllIssuances() {
        return powerAuthorizationService.authorizeQuery(null, null)
                .flatMap(issuanceService::getAllIssuancesVisibleFor);
    }

    /**
     * C1/C2 on one attestation, decided with the organization stored with it: another organization's
     * reads as not found and is traced as out of scope (FR-13). An id that is not in the tenant is
     * decided without a resource -- the platform administrator's cross-tenant view finds it in
     * another schema, everyone else gets not found from the lookup. An id that is not a UUID is
     * decided too, so a caller who may not query is still denied, and then rejected as a bad request.
     */
    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialDetails> getIssuance(@PathVariable("id") String id) {
        return storedOrganization(id)
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(organization -> powerAuthorizationService.authorizeQuery(organization.orElse(null), tracedId(id)))
                .flatMap(decision -> issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(decision, id));
    }

    /**
     * R1 (revoke), E7 (withdraw) and R2 (archive), each decided by the decision point on the
     * organization stored with the process: the token's tenant, the platform tenant's read-only
     * mode and the scope of the caller's user type are checked -- and traced -- in one place.
     */
    @PatchMapping(value = "/{id}",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> updateIssuanceStatus(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("id") String id,
            @Valid @RequestBody UpdateIssuanceStatusRequest request,
            ServerWebExchange exchange) {
        String processId = UUID.randomUUID().toString();
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);
        return switch (request.status()) {
            // The revocation workflow decides R1 on the process it loads; one that is not in the tenant
            // is decided here first, like E7 and R2, so it is traced and never answers differently.
            case REVOKED -> storedOrganization(id).hasElement().flatMap(found -> Boolean.TRUE.equals(found)
                    ? revocationWorkflow.revoke(processId, authorizationHeader, id, null, publicIssuerBaseUrl)
                    : decideThenReject(PowerAuthorizationService.REVOKE, id).then());
            case WITHDRAWN -> authorizeOnStoredIssuance(PowerAuthorizationService.WITHDRAW, id)
                    .then(Mono.defer(() -> issuanceService.withdrawIssuance(id)));
            case ARCHIVED -> authorizeOnStoredIssuance(PowerAuthorizationService.ARCHIVE, id)
                    .then(Mono.defer(() -> issuanceService.archiveIssuance(id)));
            default -> Mono.error(new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Unsupported target status: " + request.status()));
        };
    }

    /**
     * Decides an action on a stored process. A process that does not exist is decided without a
     * resource first, so a caller who may not do the action at all is denied rather than told
     * whether the id exists; then it is not found.
     */
    private Mono<AuthorizationDecision> authorizeOnStoredIssuance(String actionId, String id) {
        return storedOrganization(id)
                .flatMap(organization -> powerAuthorizationService.authorize(actionId, organization, id))
                .switchIfEmpty(Mono.defer(() -> decideThenReject(actionId, id)));
    }

    /**
     * A process that is not in the tenant: decided without a resource, then not found -- or, for an id
     * that is not a UUID, a bad request (EUD-307). The id is not echoed back -- it may be any string
     * the client sent.
     */
    private Mono<AuthorizationDecision> decideThenReject(String actionId, String id) {
        RuntimeException rejection = isUuid(id)
                ? new IssuanceNotFoundException("No issuance found for the given id")
                : new MalformedIssuanceIdException();
        return powerAuthorizationService.authorize(actionId, null, tracedId(id))
                .then(Mono.error(rejection));
    }

    /**
     * The organization stored with a process of the tenant: {@code ""} for one stored without it
     * (issued before EUD-272), which no organization matches; empty when there is no such process.
     */
    private Mono<String> storedOrganization(String id) {
        if (!isUuid(id)) {
            return Mono.empty();
        }
        return issuanceService.getIssuanceById(id)
                .map(issuance -> Objects.requireNonNullElse(issuance.getOrganizationIdentifier(), ""));
    }

    /** The path id as traced: any string the client sent that is not a process id never reaches the trace. */
    private static String tracedId(String id) {
        return isUuid(id) ? id : MALFORMED_ID;
    }

    /** Whether the path id is a process id: a UUID in its canonical form. */
    private static boolean isUuid(String id) {
        return IssuanceIds.parse(id).isPresent();
    }

    /**
     * EUD-254: the workflow only returns when the one requested delivery succeeded -- a failure is
     * raised and answered as a problem -- so a response is always 200, with one {@code responses} entry.
     */
    private ResponseEntity<IssuanceHttpResponse> toResponseEntity(IssuanceResponse response,
                                                                  String publicIssuerBaseUrl) {
        log.debug("Issuance process completed. Signed Credential present: {}, Credential Offer URI present: {}",
                response.signedCredential() != null, response.credentialOfferUri() != null);
        return withLocation(ResponseEntity.ok(), response, publicIssuerBaseUrl)
                .body(httpEnvelopeMapper.toHttpResponse(response));
    }

    /** Location of the created process, absolute because the API lives under the issuer context path (EUD-277). */
    private static ResponseEntity.BodyBuilder withLocation(ResponseEntity.BodyBuilder builder,
                                                           IssuanceResponse response, String publicIssuerBaseUrl) {
        if (response.issuanceId() != null) {
            builder.header(HttpHeaders.LOCATION, publicIssuerBaseUrl + ISSUANCES_PATH + "/" + response.issuanceId());
        }
        return builder;
    }
}
