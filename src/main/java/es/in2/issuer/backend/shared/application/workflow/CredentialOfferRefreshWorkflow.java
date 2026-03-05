package es.in2.issuer.backend.shared.application.workflow;

import reactor.core.publisher.Mono;

public interface CredentialOfferRefreshWorkflow {

    Mono<Void> refreshCredentialOffer(String refreshToken);

}
