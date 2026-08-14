package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.Oid4VciCredentialWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.CredentialRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.CredentialResponse;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.DpopValidationService;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oid4vci/v1/credential")
@RequiredArgsConstructor
public class CredentialController {

    private final Oid4VciCredentialWorkflow oid4VciCredentialWorkflow;
    private final AccessTokenService accessTokenService;
    private final UrlResolver urlResolver;
    private final DpopValidationService dpopValidationService;

    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<ResponseEntity<CredentialResponse>> issueCredential(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
            @RequestHeader(value = "DPoP", required = false) String dpopHeader,
            @RequestBody CredentialRequest credentialRequest,
            ServerWebExchange exchange) {
        String processId = UUID.randomUUID().toString();
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);
        String credentialEndpointUri = publicIssuerBaseUrl + exchange.getRequest().getPath().pathWithinApplication().value();
        return accessTokenService.resolveAccessTokenContext(authorizationHeader)
                .flatMap(token -> validateDpopBinding(token, dpopHeader, credentialEndpointUri)
                        .then(oid4VciCredentialWorkflow.createCredentialResponse(processId, credentialRequest, token, publicIssuerBaseUrl)))
                .map(verifiableCredentialResponse -> {
                    log.info("Process ID: {} - Credential response ready (deferred={})", processId, verifiableCredentialResponse.transactionId() != null);
                    if (verifiableCredentialResponse.transactionId() != null) {
                        return ResponseEntity.status(HttpStatus.ACCEPTED).body(verifiableCredentialResponse);
                    } else {
                        return ResponseEntity.status(HttpStatus.OK).body(verifiableCredentialResponse);
                    }
                })
                .doFirst(() ->
                        log.info("Process ID: {} - Creating Verifiable Credential...", processId))
                .doOnSuccess(credentialOffer ->
                        log.info("Process ID: {} - Authorization Server Metadata generated successfully.", processId));
    }

    // RFC 9449 §5-7: a DPoP-bound access token (cnf.jkt present) must be presented here
    // together with a DPoP proof for the same key, or a stolen bearer-style token could be
    // replayed with any key to fetch a credential. Tokens without cnf.jkt (DPoP not required
    // for the issuing tenant profile) are unaffected.
    private Mono<Void> validateDpopBinding(AccessTokenContext token, String dpopHeader, String credentialEndpointUri) {
        if (token.cnfJkt() == null) {
            return Mono.empty();
        }
        if (dpopHeader == null || dpopHeader.isBlank()) {
            return Mono.error(new InvalidTokenException("Missing DPoP proof for a DPoP-bound access token"));
        }
        return Mono.fromCallable(() -> dpopValidationService.validate(dpopHeader, "POST", credentialEndpointUri, token.rawToken()))
                .flatMap(actualJkt -> {
                    if (!token.cnfJkt().equals(actualJkt)) {
                        return Mono.error(new InvalidTokenException("DPoP proof key does not match the access token binding"));
                    }
                    return Mono.empty();
                });
    }

}
