package es.in2.issuer.backend.oidc4vci.domain.repository;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import reactor.core.publisher.Mono;

import java.time.Instant;

public interface CredentialOfferCacheRepository {
    Mono<String> saveCredentialOffer(CredentialOfferData credentialOfferData);
    Mono<CredentialOfferData> findCredentialOfferById(String id);

    /** When an offer created now stops being redeemable. */
    Instant newOfferExpiry();
}
