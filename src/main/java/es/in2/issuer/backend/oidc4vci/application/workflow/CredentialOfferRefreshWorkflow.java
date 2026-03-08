package es.in2.issuer.backend.oidc4vci.application.workflow;

import reactor.core.publisher.Mono;

public interface CredentialOfferRefreshWorkflow {
    Mono<Void> refreshCredentialOffer(String credentialOfferRefreshToken);
}
