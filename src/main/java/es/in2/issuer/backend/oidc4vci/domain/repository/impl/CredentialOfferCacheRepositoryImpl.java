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

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialOfferCacheRepositoryImpl implements CredentialOfferCacheRepository {

    private final TransientStore<CredentialOfferData> cacheStore;

    @Override
    public Mono<String> saveCredentialOffer(String issuanceId, CredentialOfferData credentialOfferData) {
        return cacheStore.add(issuanceId, credentialOfferData);
    }

    @Override
    public Mono<CredentialOfferData> findCredentialOfferById(String id) {
        return cacheStore.get(id)
                .switchIfEmpty(Mono.error(
                        new CredentialOfferNotFoundException("CredentialOffer not found for issuanceId: " + id)))
                .onErrorMap(NoSuchElementException.class, _ ->
                        new CredentialOfferNotFoundException("CredentialOffer not found for issuanceId: " + id))
                .doOnNext(_ ->
                        log.debug("CredentialOffer found for issuanceId: {}", id)
                )
                .flatMap(customCredentialOffer ->
                        cacheStore.delete(id).thenReturn(customCredentialOffer)
                );
    }
}
