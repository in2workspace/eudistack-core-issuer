package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.ISSUER_BASE_URL_CONTEXT_KEY;

@RestController
@RequestMapping("/oauth/token")
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;
    private final IssuerProperties issuerProperties;

    @PostMapping(
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<TokenResponse> exchangeToken(
            TokenRequest tokenRequest,
            @RequestHeader(value = "DPoP", required = false) String dpopHeader,
            ServerWebExchange exchange
    ) {
        return Mono.deferContextual(ctx -> {
            String baseUrl = ctx.getOrDefault(ISSUER_BASE_URL_CONTEXT_KEY, issuerProperties.getIssuerBackendUrl());
            String tokenEndpointUri = baseUrl + exchange.getRequest().getURI().getPath();
            return tokenService.exchangeToken(tokenRequest, dpopHeader, tokenEndpointUri);
        });
    }
}
