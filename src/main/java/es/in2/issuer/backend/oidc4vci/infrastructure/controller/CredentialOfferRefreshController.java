package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
public class CredentialOfferRefreshController {

    private final CredentialOfferRefreshWorkflow credentialOfferRefreshWorkflow;
    private final UrlResolver urlResolver;

    @PostMapping("/credential-offer/refresh/{credentialOfferRefreshToken}")
    @ResponseStatus(HttpStatus.OK)
    public Mono<Void> refreshCredentialOffer(@PathVariable String credentialOfferRefreshToken,
                                             ServerWebExchange exchange) {
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);
        return credentialOfferRefreshWorkflow.refreshCredentialOffer(credentialOfferRefreshToken, publicIssuerBaseUrl);
    }
}
