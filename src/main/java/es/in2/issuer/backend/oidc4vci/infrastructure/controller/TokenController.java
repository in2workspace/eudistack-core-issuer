package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.oidc4vci.domain.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.AUTHORIZATION_CODE_GRANT_TYPE;

@RestController
@RequestMapping("/oauth/token")
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    @PostMapping(
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public Mono<TokenResponse> handleTokenRequest(
            TokenRequest tokenRequest,
            @RequestHeader(value = "DPoP", required = false) String dpopHeader,
            ServerWebExchange exchange
    ) {
        if (AUTHORIZATION_CODE_GRANT_TYPE.equals(tokenRequest.grantType())) {
            String tokenEndpointUri = exchange.getRequest().getURI().toString();
            return tokenService.generateTokenResponseForAuthorizationCode(
                    tokenRequest.code(),
                    tokenRequest.redirectUri(),
                    tokenRequest.codeVerifier(),
                    dpopHeader,
                    tokenEndpointUri
            );
        }

        return tokenService.generateTokenResponse(
                tokenRequest.grantType(),
                tokenRequest.preAuthorizedCode(),
                tokenRequest.txCode(),
                tokenRequest.refreshToken());
    }
}