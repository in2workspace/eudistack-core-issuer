package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dtos.UpdateIssuanceStatusRequest;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceHttpResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
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

import java.util.List;
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
                .map(this::toResponseEntity);
    }

    /** C1/C2 (EUD-253): the decision's scope says whether the caller sees its organization or the whole tenant. */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<IssuanceList> getAllIssuances() {
        return powerAuthorizationService.authorize(PowerAuthorizationService.QUERY, null, null)
                .flatMap(issuanceService::getAllIssuancesVisibleFor);
    }

    /**
     * C1 on one attestation, decided with the organization stored with it: another organization's
     * reads as not found and is traced as out of scope (FR-13). An id that is not in the tenant is
     * decided without a resource -- the platform administrator's cross-tenant view finds it in
     * another schema, everyone else gets not found from the lookup.
     */
    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialDetails> getIssuance(@PathVariable("id") String id) {
        return storedOrganization(id)
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(organization -> powerAuthorizationService.authorize(
                        PowerAuthorizationService.QUERY, organization.orElse(null), id))
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
                    : decideThenNotFound(PowerAuthorizationService.REVOKE, id).then());
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
                .switchIfEmpty(Mono.defer(() -> decideThenNotFound(actionId, id)));
    }

    /**
     * A process that is not in the tenant: decided without a resource, then not found. The id is not
     * echoed back -- it may be any string the client sent.
     */
    private Mono<AuthorizationDecision> decideThenNotFound(String actionId, String id) {
        return powerAuthorizationService.authorize(actionId, null, isUuid(id) ? id : MALFORMED_ID)
                .then(Mono.error(new IssuanceNotFoundException("No issuance found for the given id")));
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

    /** Whether the path id is a process id; any other string the client sent never reaches the trace. */
    private static boolean isUuid(String id) {
        try {
            UUID.fromString(id);
            return true;
        } catch (IllegalArgumentException _) {
            return false;
        }
    }

    private ResponseEntity<IssuanceHttpResponse> toResponseEntity(IssuanceResponse response) {
        List<DeliveryResult> results = response.deliveryResults();
        boolean hasDeliveryResults = results != null && !results.isEmpty();

        log.debug("Issuance process completed. Signed Credential present: {}, Credential Offer URI present: {}, delivery results: {}",
                response.signedCredential() != null, response.credentialOfferUri() != null,
                hasDeliveryResults ? results.size() : 0);

        // No channel executed at all -- the pre-flight guard rejected before anything ran. Not
        // modeled by D-5's responses[] envelope (that requires >=1 executed channel); every guard
        // rejection is a thrown exception handled by IssuanceExceptionHandler before this method is
        // ever reached, so this is the harmless residual default for an empty/absent result set.
        if (!hasDeliveryResults) {
            return ResponseEntity.accepted().build();
        }

        IssuanceHttpResponse body = httpEnvelopeMapper.toHttpResponse(response);
        boolean anyChannelFailed = results.stream().anyMatch(r -> r.status() == DeliveryResult.DeliveryOutcome.FAILED);
        boolean anyChannelSucceeded = results.stream().anyMatch(r -> r.status() != DeliveryResult.DeliveryOutcome.FAILED);

        // Mixed outcome (EUD-167 D-5 / AD-1 B, RFC 4918 §11.1/§13): at least one requested channel
        // completed and at least one failed, regardless of which channel is which -- supersedes
        // EUD-168's AD-11 (500 whenever the direct mode failed, 200 whenever it didn't), which predates
        // and conflicts with D-5's general contract (PO decision, see EUD-167/spec-deltas.md D-6).
        // A request where nothing at all completed never reaches this branch -- the workflow re-raises
        // the original error upstream (assembleOutcome) so it renders as its own problem detail instead
        // of being flattened here.
        if (anyChannelFailed && anyChannelSucceeded) {
            log.warn("Partial issuance outcome (mixed delivery results): {}", results);
            return ResponseEntity.status(HttpStatus.MULTI_STATUS).body(body);
        }

        // Every requested channel failed (e.g. wallet-only with the wallet dependency down, direct
        // never attempted so assembleOutcome had nothing to re-raise): not mixed, not a success.
        if (anyChannelFailed) {
            log.warn("Issuance fully failed across all requested channels: {}", results);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
        }

        // D-5: 202 wallet-only is retired -- a fully successful request is always 200.
        return ResponseEntity.ok(body);
    }
}
