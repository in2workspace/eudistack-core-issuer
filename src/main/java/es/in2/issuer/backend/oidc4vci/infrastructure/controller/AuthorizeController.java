package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.domain.service.AuthorizationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_AUTHORIZE_PATH;

@RestController
@RequestMapping(OID4VCI_AUTHORIZE_PATH)
@RequiredArgsConstructor
public class AuthorizeController {

    private final AuthorizationService authorizationService;

    @GetMapping
    public Mono<Void> authorize(
            @RequestParam(value = "request_uri", required = false) String requestUri,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "issuer_state", required = false) String issuerState,
            ServerHttpResponse response
    ) {
        return authorizationService.authorize(
                requestUri, clientId, responseType, scope, state,
                codeChallenge, codeChallengeMethod, redirectUri, issuerState
        ).flatMap(uri -> {
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(uri);
            return response.setComplete();
        });
    }
}
