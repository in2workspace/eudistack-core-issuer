package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.ParService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.service.ClientAttestationValidationService.HEADER_CLIENT_ATTESTATION;
import static es.in2.issuer.backend.shared.domain.service.ClientAttestationValidationService.HEADER_CLIENT_ATTESTATION_POP;
import static es.in2.issuer.backend.shared.domain.util.Constants.ISSUER_BASE_URL_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_PAR_PATH;

@RestController
@RequestMapping(OID4VCI_PAR_PATH)
@RequiredArgsConstructor
public class ParController {

    private final ParService parService;
    private final IssuerProperties issuerProperties;

    @PostMapping(
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<PushedAuthorizationResponse> pushAuthorizationRequest(
            PushedAuthorizationRequest request,
            @RequestHeader(value = "DPoP", required = false) String dpopHeader,
            @RequestHeader(value = HEADER_CLIENT_ATTESTATION, required = false) String wiaHeader,
            @RequestHeader(value = HEADER_CLIENT_ATTESTATION_POP, required = false) String wiaPopHeader,
            ServerWebExchange exchange
    ) {
        return Mono.deferContextual(ctx -> {
            String publicIssuerUrl = ctx.getOrDefault(ISSUER_BASE_URL_CONTEXT_KEY, issuerProperties.getIssuerBackendUrl());
            String requestUri = publicIssuerUrl + exchange.getRequest().getURI().getPath();
            return parService.pushAuthorizationRequest(request, dpopHeader, wiaHeader, wiaPopHeader, requestUri, publicIssuerUrl);
        });
    }
}
