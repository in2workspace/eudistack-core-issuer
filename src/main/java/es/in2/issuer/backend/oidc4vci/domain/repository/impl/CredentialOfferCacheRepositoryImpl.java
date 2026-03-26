package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.NoSuchElementException;

import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferCacheRepositoryImpl implements CredentialOfferCacheRepository {

    private final TransientStore<CredentialOfferData> cacheStore;
    private final TransientStore<String> credentialOfferIndexCacheStore;


    @Override
    public Mono<String> saveCredentialOffer(CredentialOfferData credentialOfferData) {
        return generateCustomNonce()
                .flatMap(newNonce -> cacheStore.add(newNonce, credentialOfferData)
                        .flatMap(savedNonce -> updateActiveNonce(credentialOfferData.issuanceId(), savedNonce)));
    }

    @Override
    public Mono<CredentialOfferData> consumeCredentialOffer(String id) {
        return cacheStore.getAndDelete(id)
                .onErrorMap(NoSuchElementException.class,
                        e -> new CredentialOfferNotFoundException("CredentialOffer not found for nonce: " + id))
                .doOnNext(data -> log.debug("CredentialOffer found for nonce: {}", id));
    }

    private Mono<String> updateActiveNonce(String issuanceId, String newNonce) {
        if (issuanceId == null) return Mono.just(newNonce);

        return credentialOfferIndexCacheStore.getAndDelete(issuanceId)
                .flatMap(oldNonce -> {
                    log.debug("Invalidating previous nonce {} for issuanceId {}", oldNonce, issuanceId);
                    return cacheStore.delete(oldNonce);
                })
                .onErrorResume(NoSuchElementException.class, e -> Mono.empty())
                .then(credentialOfferIndexCacheStore.add(issuanceId, newNonce))
                .thenReturn(newNonce);
    }
}