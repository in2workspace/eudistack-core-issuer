package es.in2.issuer.backend.backoffice.domain.service;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferGrants;
import reactor.core.publisher.Mono;

public interface CredentialOfferService {
    Mono<CredentialOfferData> buildCredentialOffer(String credentialType, CredentialOfferGrants grants, String credentialEmail, String pin);
    Mono<String> createCredentialOfferUriResponse(String nonce);
}
