package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialOfferCacheRepositoryImplTest {

    @Mock
    private TransientStore<CredentialOfferData> cacheStore;

    @Mock
    private TransientStore<String> credentialOfferIndexCacheStore;

    private CredentialOfferCacheRepositoryImpl service;

    @BeforeEach
    void setUp() {
        service = new CredentialOfferCacheRepositoryImpl(cacheStore, credentialOfferIndexCacheStore);
    }

    @Test
    void testSaveCredentialOffer() {
        CredentialOfferData credentialOfferData = CredentialOfferData.builder().build();
        String expectedNonce = "testNonce";

        when(cacheStore.add(any(String.class), eq(credentialOfferData))).thenReturn(Mono.just(expectedNonce));

        StepVerifier.create(service.saveCredentialOffer(credentialOfferData))
                .expectNext(expectedNonce)
                .verifyComplete();

        verify(cacheStore, times(1)).add(any(String.class), eq(credentialOfferData));
        verify(cacheStore, never()).getAndDelete(anyString());
    }

    @Test
    void testConsumeCredentialOffer() {
        String nonce = "testNonce";
        CredentialOfferData credentialOfferData = CredentialOfferData.builder().build();

        when(cacheStore.getAndDelete(nonce)).thenReturn(Mono.just(credentialOfferData));

        StepVerifier.create(service.consumeCredentialOffer(nonce))
                .expectNextMatches(retrievedOffer -> retrievedOffer.equals(credentialOfferData))
                .verifyComplete();

        verify(cacheStore, times(1)).getAndDelete(nonce);
    }

    @Test
    void testConsumeCredentialOfferNotFound() {
        String nonce = "testNonce";

        when(cacheStore.getAndDelete(nonce))
                .thenReturn(Mono.error(new NoSuchElementException("Value is not present.")));

        StepVerifier.create(service.consumeCredentialOffer(nonce))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining("CredentialOffer not found for nonce: " + nonce))
                .verify();

        verify(cacheStore, times(1)).getAndDelete(nonce);
    }

    @Test
    void saveCredentialOffer_whenRefreshGeneratesNewNonce_previousNonceIsInvalidated() {
        // Arrange
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CacheStore<String> indexCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CredentialOfferCacheRepositoryImpl repository = new CredentialOfferCacheRepositoryImpl(realCache, indexCache);

        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-abc")
                .build();

        // Act
        String oldNonce = repository.saveCredentialOffer(offerData).block();
        repository.saveCredentialOffer(offerData).block();

        // Assert - old nonce has been invalidated
        StepVerifier.create(repository.consumeCredentialOffer(oldNonce))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining(oldNonce))
                .verify();
    }

    @Test
    void saveCredentialOffer_whenRefreshWithSameIssuanceId_previousEntryIsAtomicallyReplaced() {
        // Arrange
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CacheStore<String> indexCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CredentialOfferCacheRepositoryImpl repository = new CredentialOfferCacheRepositoryImpl(realCache, indexCache);

        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-abc")
                .build();

        String activeId = repository.saveCredentialOffer(offerData).block();

        // Act
        repository.saveCredentialOffer(offerData).block();

        // Assert
        StepVerifier.create(repository.consumeCredentialOffer(activeId))
                .expectError(CredentialOfferNotFoundException.class)
                .verify();
    }

    @Test
    void consumeCredentialOffer_whenNewNonceUsedAfterRefresh_returnsCorrectData() {
        // Arrange
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CacheStore<String> indexCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CredentialOfferCacheRepositoryImpl repository = new CredentialOfferCacheRepositoryImpl(realCache, indexCache);

        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-xyz")
                .build();

        // Act
        repository.saveCredentialOffer(offerData).block();
        String newNonce = repository.saveCredentialOffer(offerData).block();

        // Assert
        StepVerifier.create(repository.consumeCredentialOffer(newNonce))
                .expectNext(offerData)
                .verifyComplete();
    }

    @Test
    void consumeCredentialOffer_whenTtlExpires_throwsCredentialOfferNotFoundException() throws InterruptedException {
        // Arrange
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(50, TimeUnit.MILLISECONDS);
        CacheStore<String> indexCache = new CacheStore<>(50, TimeUnit.MILLISECONDS);
        CredentialOfferCacheRepositoryImpl repository = new CredentialOfferCacheRepositoryImpl(realCache, indexCache);

        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-ttl")
                .build();

        String nonce = repository.saveCredentialOffer(offerData).block();

        // Act
        Thread.sleep(100);

        // Assert
        StepVerifier.create(repository.consumeCredentialOffer(nonce))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining(nonce))
                .verify();
    }
}
