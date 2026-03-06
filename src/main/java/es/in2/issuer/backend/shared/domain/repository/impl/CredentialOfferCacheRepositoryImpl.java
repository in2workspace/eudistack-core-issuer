package es.in2.issuer.backend.shared.domain.repository.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Utils.generateCustomNonce;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferCacheRepositoryImpl implements CredentialOfferCacheRepository {

    private final TransientStore<CredentialOfferData> cacheStore;

    @Override
    public Mono<String> saveCredentialOffer(CredentialOfferData credentialOfferData) {
        return generateCustomNonce().flatMap(nonce -> cacheStore.add(nonce, credentialOfferData));
    }

    @Override
    public Mono<CredentialOfferData> findCredentialOfferById(String id) {
        return cacheStore.get(id)
                .switchIfEmpty(Mono.error(
                        new CredentialOfferNotFoundException("CredentialOffer not found for nonce: " + id))
                )
                .doOnNext(customCredentialOffer ->
                        log.debug("CredentialOffer found for nonce: {}", id)
                )
                .flatMap(customCredentialOffer ->
                        cacheStore.delete(id).thenReturn(customCredentialOffer)
                );
    }

}
