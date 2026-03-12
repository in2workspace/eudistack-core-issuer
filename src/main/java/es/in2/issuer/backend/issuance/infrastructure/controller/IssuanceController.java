package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.dtos.UpdateIssuanceStatusRequest;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
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
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;

@Slf4j
@RestController
@RequestMapping(ISSUANCES_PATH)
@RequiredArgsConstructor
public class IssuanceController {

    private final IssuanceWorkflow issuanceWorkflow;
    private final IssuanceService issuanceService;
    private final AccessTokenService accessTokenService;
    private final RevocationWorkflow revocationWorkflow;

    @PostMapping(
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<IssuanceResponse>> createIssuance(
            @RequestHeader(name = "X-Id-Token", required = false) String idToken,
            @Valid @RequestBody IssuanceRequest request) {
        String processId = UUID.randomUUID().toString();
        return issuanceWorkflow.issueCredential(processId, request, idToken)
                .map(this::toResponseEntity);
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<IssuanceList> getAllIssuances(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        return accessTokenService.getOrganizationContext(authorizationHeader)
                .flatMap(ctx -> issuanceService.getAllIssuancesVisibleFor(
                        ctx.organizationIdentifier(), ctx.sysAdmin()));
    }

    @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<CredentialDetails> getIssuance(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("id") String id) {
        return accessTokenService.getOrganizationContext(authorizationHeader)
                .flatMap(ctx -> issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(
                        ctx.organizationIdentifier(), id, ctx.sysAdmin()));
    }

    @PatchMapping(value = "/{id}",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> updateIssuanceStatus(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @PathVariable("id") String id,
            @Valid @RequestBody UpdateIssuanceStatusRequest request) {
        String processId = UUID.randomUUID().toString();
        return switch (request.status()) {
            case WITHDRAWN -> issuanceService.withdrawIssuance(id);
            case REVOKED -> revocationWorkflow.revoke(processId, authorizationHeader, id);
            default -> Mono.error(new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Unsupported target status: " + request.status()));
        };
    }

    private ResponseEntity<IssuanceResponse> toResponseEntity(IssuanceResponse response) {
        if (response.credentialOfferUri() != null) {
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

}