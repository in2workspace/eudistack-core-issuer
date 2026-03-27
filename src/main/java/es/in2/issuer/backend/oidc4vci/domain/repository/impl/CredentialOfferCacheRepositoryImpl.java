package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
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

    private final TransientStore<CredentialOfferData> credentialOfferByNonceCache;
    private final TransientStore<String> oldNonceByIssuanceIdCache;


    @Override
    public Mono<String> saveCredentialOffer(CredentialOfferData credentialOfferData) {
        return generateCustomNonce()
                .flatMap(newNonce -> credentialOfferByNonceCache.add(newNonce, credentialOfferData)
                        .flatMap(savedNonce -> updateActiveNonce(credentialOfferData.issuanceId(), savedNonce)));
    }

    @Override
    public Mono<CredentialOfferData> consumeCredentialOffer(String nonce) {
        return credentialOfferByNonceCache.getAndDelete(nonce)
                .onErrorMap(NoSuchElementException.class,
                        _ -> new CredentialOfferNotFoundException("CredentialOffer not found for nonce: " + nonce))
                .doOnNext(_ -> log.debug("CredentialOffer found for nonce: {}", nonce));
    }

    private Mono<String> updateActiveNonce(String issuanceId, String newNonce) {
        if (issuanceId == null) return Mono.just(newNonce);

        return oldNonceByIssuanceIdCache.getAndDelete(issuanceId)
                .flatMap(oldNonce -> {
                    log.debug("Invalidating previous nonce {} for issuanceId {}", oldNonce, issuanceId);
                    return credentialOfferByNonceCache.delete(oldNonce);
                })
                .onErrorResume(NoSuchElementException.class, _ -> Mono.empty())
                .then(oldNonceByIssuanceIdCache.add(issuanceId, newNonce))
                .thenReturn(newNonce);
    }
}