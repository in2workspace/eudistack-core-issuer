package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.oidc4vci.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferCacheRepositoryImpl implements CredentialOfferCacheRepository {

    private final TransientStore<CredentialOfferData> cacheStore;
    private Cache<String, String> activeNonceByIssuanceId;

    @PostConstruct
    void initActiveNonceIndex() {
        long ttlSeconds = Math.max(1L, cacheStore.getExpiryInSeconds().block());
        activeNonceByIssuanceId = CacheBuilder.newBuilder()
                .maximumSize(10_000L)
                .expireAfterWrite(ttlSeconds, TimeUnit.SECONDS)
                .build();
    }

    @Override
    public Mono<String> saveCredentialOffer(CredentialOfferData credentialOfferData) {
        return generateCustomNonce()
                .flatMap(nonce -> cacheStore.add(nonce, credentialOfferData)
                        .flatMap(savedNonce -> swapNonceAndInvalidateOld(credentialOfferData.issuanceId(), savedNonce)));
    }


    private Mono<String> swapNonceAndInvalidateOld(String issuanceId, String newNonce) {
        if (issuanceId == null) return Mono.just(newNonce);
        String[] oldNonceRef = {null};
        activeNonceByIssuanceId.asMap().compute(issuanceId,
                (id, old) -> { oldNonceRef[0] = old; return newNonce; });
        if (oldNonceRef[0] != null) {
            log.debug("Invalidating previous nonce {} for issuanceId {}", oldNonceRef[0], issuanceId);
            return cacheStore.delete(oldNonceRef[0]).thenReturn(newNonce);
        }
        return Mono.just(newNonce);
    }

    @Override
    public Mono<CredentialOfferData> findCredentialOfferById(String id) {
        return cacheStore.get(id)
                .onErrorResume(NoSuchElementException.class, e -> Mono.empty())
                .switchIfEmpty(Mono.error(
                        new CredentialOfferNotFoundException("CredentialOffer not found for nonce: " + id)))
                .doOnNext(data -> log.debug("CredentialOffer found for nonce: {}", id))
                .flatMap(data -> {
                    if (data.issuanceId() != null) {
                        activeNonceByIssuanceId.asMap().remove(data.issuanceId(), id);
                    }
                    return cacheStore.delete(id).thenReturn(data);
                });
    }
}
