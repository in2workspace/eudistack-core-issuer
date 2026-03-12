package es.in2.issuer.backend.oidc4vci.application.workflow;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOffer;
import reactor.core.publisher.Mono;

public interface CredentialOfferWorkflow {
    Mono<CredentialOffer> findCredentialOfferById(String processId, String id);
}
