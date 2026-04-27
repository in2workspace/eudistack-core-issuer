package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.reactive.result.view.Rendering;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Controller
@RequiredArgsConstructor
public class CredentialOfferRefreshController {

    private final CredentialOfferRefreshWorkflow credentialOfferRefreshWorkflow;
    private final UrlResolver urlResolver;

    @GetMapping("/credential-offer/refresh/{credentialOfferRefreshToken}")
    public Mono<Rendering> refreshCredentialOffer(@PathVariable String credentialOfferRefreshToken,
                                                  ServerWebExchange exchange) {
        String publicIssuerBaseUrl = urlResolver.publicIssuerBaseUrl(exchange);
        return credentialOfferRefreshWorkflow.refreshCredentialOffer(credentialOfferRefreshToken, publicIssuerBaseUrl)
                .then(Mono.just(Rendering.view("credential-offer-refresh-success").build()))
                .onErrorResume(ex -> {
                    log.warn("Credential offer refresh failed for token {}: {}", credentialOfferRefreshToken, ex.getMessage());
                    return Mono.just(Rendering.view("credential-offer-refresh-error")
                            .modelAttribute("errorMessage", ex.getMessage())
                            .build());
                });
    }
}
