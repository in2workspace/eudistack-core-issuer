package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialOfferRefreshWorkflow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.reactive.result.view.Rendering;
import reactor.core.publisher.Mono;

@Slf4j
@Controller
@RequiredArgsConstructor
public class CredentialOfferRefreshController {

    private final CredentialOfferRefreshWorkflow credentialOfferRefreshWorkflow;

    @GetMapping("/credential-offer/refresh/{credentialOfferRefreshToken}")
    public Mono<Rendering> refreshCredentialOffer(@PathVariable String credentialOfferRefreshToken) {
        return credentialOfferRefreshWorkflow.refreshCredentialOffer(credentialOfferRefreshToken)
                .then(Mono.just(Rendering.view("credential-offer-refresh-success").build()))
                .onErrorResume(ex -> {
                    log.warn("Credential offer refresh failed for token {}: {}", credentialOfferRefreshToken, ex.getMessage());
                    return Mono.just(Rendering.view("credential-offer-refresh-error")
                            .modelAttribute("errorMessage", ex.getMessage())
                            .build());
                });
    }

}
