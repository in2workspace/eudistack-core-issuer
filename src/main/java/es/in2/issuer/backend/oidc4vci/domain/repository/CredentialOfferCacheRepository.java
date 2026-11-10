package es.in2.issuer.backend.oidc4vci.domain.repository;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import reactor.core.publisher.Mono;

public interface CredentialOfferCacheRepository {
    Mono<String> saveCredentialOffer(CredentialOfferData credentialOfferData);
    Mono<CredentialOfferData> findCredentialOfferById(String id);

    /**
     * Withdraws an offer: from then on it answers like one already used (410). An unknown or
     * already purged nonce is a no-op.
     */
    Mono<Void> invalidateCredentialOffer(String id);
}
