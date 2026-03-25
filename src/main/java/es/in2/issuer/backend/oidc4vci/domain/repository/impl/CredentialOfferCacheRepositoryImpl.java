package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ConcurrentHashMap;

import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferCacheRepositoryImpl implements CredentialOfferCacheRepository {

    private final TransientStore<CredentialOfferData> cacheStore;
    private final Map<String, String> activeNonceByIssuanceId = new ConcurrentHashMap<>();

    @Override
    public Mono<String> saveCredentialOffer(CredentialOfferData credentialOfferData) {
        return invalidatePreviousNonce(credentialOfferData.issuanceId())
                .then(generateCustomNonce()
                        .flatMap(nonce -> cacheStore.add(nonce, credentialOfferData)
                                .doOnNext(savedNonce -> {
                                    if (credentialOfferData.issuanceId() != null) {
                                        activeNonceByIssuanceId.put(credentialOfferData.issuanceId(), savedNonce);
                                    }
                                })
                        )
                );
    }

    private Mono<Void> invalidatePreviousNonce(String issuanceId) {
        if (issuanceId == null) return Mono.empty();
        String previousNonce = activeNonceByIssuanceId.remove(issuanceId);
        if (previousNonce == null) return Mono.empty();
        log.debug("Invalidating previous nonce {} for issuanceId {}", previousNonce, issuanceId);
        return cacheStore.delete(previousNonce);
    }

    @Override
    public Mono<CredentialOfferData> findCredentialOfferById(String id) {
        return cacheStore.get(id)
                .onErrorMap(NoSuchElementException.class, e ->
                        new CredentialOfferNotFoundException("CredentialOffer not found for nonce: " + id))
                .switchIfEmpty(Mono.error(
                        new CredentialOfferNotFoundException("CredentialOffer not found for nonce: " + id)))
                .doOnNext(customCredentialOffer ->
                        log.debug("CredentialOffer found for nonce: {}", id)
                )
                .flatMap(customCredentialOffer -> {
                    if (customCredentialOffer.issuanceId() != null) {
                        activeNonceByIssuanceId.remove(customCredentialOffer.issuanceId(), id);
                    }
                    return cacheStore.delete(id).thenReturn(customCredentialOffer);
                });
    }
}
