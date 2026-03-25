package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialOfferCacheRepositoryImplTest {

    @Mock
    private TransientStore<CredentialOfferData> cacheStore;

    @InjectMocks
    private CredentialOfferCacheRepositoryImpl service;

    @Test
    void testSaveCredentialOffer() {
        CredentialOfferData credentialOfferData = CredentialOfferData.builder().build();
        String expectedNonce = "testNonce";

        when(cacheStore.add(any(String.class), eq(credentialOfferData))).thenReturn(Mono.just(expectedNonce));

        StepVerifier.create(service.saveCredentialOffer(credentialOfferData))
                .expectNext(expectedNonce)
                .verifyComplete();

        verify(cacheStore, times(1)).add(any(String.class), eq(credentialOfferData));
    }

    @Test
    void testFindCredentialOfferById() {
        String nonce = "testNonce";
        CredentialOfferData credentialOfferData = CredentialOfferData.builder().build();

        when(cacheStore.get(nonce)).thenReturn(Mono.just(credentialOfferData));
        when(cacheStore.delete(nonce)).thenReturn(Mono.empty());

        StepVerifier.create(service.findCredentialOfferById(nonce))
                .expectNextMatches(retrievedOffer -> retrievedOffer.equals(credentialOfferData))
                .verifyComplete();

        verify(cacheStore, times(1)).delete(nonce);
    }

    @Test
    void testFindCredentialOfferByIdNotFound() {
        String nonce = "testNonce";
        when(cacheStore.get(nonce)).thenReturn(Mono.empty());

        StepVerifier.create(service.findCredentialOfferById(nonce))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining("CredentialOffer not found for nonce: " + nonce))
                .verify();

        verify(cacheStore, never()).delete(anyString());
    }

    @Test
    void saveCredentialOffer_whenRefreshGeneratesNewNonce_previousNonceIsInvalidated() {
        // Arrange
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CredentialOfferCacheRepositoryImpl repository = new CredentialOfferCacheRepositoryImpl(realCache);
        repository.initActiveNonceIndex(); // simula @PostConstruct fuera del contexto de Spring

        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-abc")
                .build();

        // Act
        String oldNonce = repository.saveCredentialOffer(offerData).block();
        repository.saveCredentialOffer(offerData).block();

        // Assert
        StepVerifier.create(repository.findCredentialOfferById(oldNonce))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining(oldNonce))
                .verify();
    }

    @Test
    void findCredentialOfferById_whenNewNonceUsedAfterRefresh_returnsCorrectData() {
        // Arrange
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CredentialOfferCacheRepositoryImpl repository = new CredentialOfferCacheRepositoryImpl(realCache);
        repository.initActiveNonceIndex(); // simula @PostConstruct fuera del contexto de Spring

        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-xyz")
                .build();

        // Act
        repository.saveCredentialOffer(offerData).block();
        String newNonce = repository.saveCredentialOffer(offerData).block();

        // Assert
        StepVerifier.create(repository.findCredentialOfferById(newNonce))
                .expectNext(offerData)
                .verifyComplete();
    }

    @Test
    void findCredentialOfferById_whenTtlExpires_throwsCredentialOfferNotFoundException() throws InterruptedException {
        // Arrange — FIX 3: TTL mínimo práctico (50 ms) para no ralentizar la suite
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(50, TimeUnit.MILLISECONDS);
        CredentialOfferCacheRepositoryImpl repository = new CredentialOfferCacheRepositoryImpl(realCache);
        repository.initActiveNonceIndex(); // simula @PostConstruct fuera del contexto de Spring

        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-ttl")
                .build();

        String nonce = repository.saveCredentialOffer(offerData).block();

        // Act — esperar a que el TTL expire (100 ms >> 50 ms de TTL)
        Thread.sleep(100);

        // Assert
        StepVerifier.create(repository.findCredentialOfferById(nonce))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining(nonce))
                .verify();
    }
}
