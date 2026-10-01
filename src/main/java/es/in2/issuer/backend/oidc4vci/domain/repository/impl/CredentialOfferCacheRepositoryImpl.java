package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import es.in2.issuer.backend.oidc4vci.domain.exception.CredentialOfferNoLongerAvailableException;
import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;

import static es.in2.issuer.backend.shared.domain.util.Constants.CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME;
import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferCacheRepositoryImpl implements CredentialOfferCacheRepository {

    private static final Duration CREDENTIAL_OFFER_LIFETIME = Duration.ofMinutes(CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME);

    private final TransientStore<CredentialOfferData> cacheStore;
    private final Clock clock;

    @Override
    public Mono<String> saveCredentialOffer(CredentialOfferData credentialOfferData) {
        CredentialOfferData withExpiry = credentialOfferData.toBuilder()
                .expiresAt(clock.instant().plus(CREDENTIAL_OFFER_LIFETIME))
                .consumed(false)
                .build();
        return generateCustomNonce().flatMap(nonce -> cacheStore.add(nonce, withExpiry));
    }

    /**
     * Redeems a credential offer: returns it once and marks it as consumed. The entry is kept
     * (not deleted) so that later lookups within the store's retention window can tell an
     * expired or consumed offer (410) apart from one that never existed (404).
     */
    @Override
    public Mono<CredentialOfferData> findCredentialOfferById(String id) {
        return cacheStore.get(id)
                .switchIfEmpty(Mono.error(
                        new CredentialOfferNotFoundException("CredentialOffer not found for nonce: " + id))
                )
                .flatMap(credentialOfferData -> {
                    if (!credentialOfferData.isRedeemableAt(clock.instant())) {
                        log.info("CredentialOffer no longer available: expiresAt={}, consumed={}",
                                credentialOfferData.expiresAt(), credentialOfferData.consumed());
                        return Mono.error(credentialOfferData.consumed()
                                ? CredentialOfferNoLongerAvailableException.alreadyUsed()
                                : CredentialOfferNoLongerAvailableException.expired());
                    }
                    log.debug("CredentialOffer found for nonce: {}", id);
                    return cacheStore.add(id, credentialOfferData.markConsumed())
                            .thenReturn(credentialOfferData);
                });
    }
}