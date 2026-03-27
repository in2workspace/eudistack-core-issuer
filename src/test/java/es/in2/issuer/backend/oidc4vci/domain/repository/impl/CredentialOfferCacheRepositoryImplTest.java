package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialOfferCacheRepositoryImplTest {

    @Mock
    private TransientStore<CredentialOfferData> credentialOfferByNonceCache;

    @Mock
    private TransientStore<String> oldNonceByIssuanceIdCache;

    private CredentialOfferCacheRepositoryImpl credentialOfferCacheRepository;

    @BeforeEach
    void setUp() {
        credentialOfferCacheRepository = new CredentialOfferCacheRepositoryImpl(credentialOfferByNonceCache, oldNonceByIssuanceIdCache);
    }

    @Test
    void saveCredentialOffer_NullIssuanceId_ReturnsNonce() {
        // Arrange
        CredentialOfferData credentialOfferData = CredentialOfferData.builder().build();
        String expectedNonce = "test-nonce";
        doReturn(Mono.just(expectedNonce)).when(credentialOfferByNonceCache).add(anyString(), any());

        // Act & Assert
        StepVerifier.create(credentialOfferCacheRepository.saveCredentialOffer(credentialOfferData))
                .expectNext(expectedNonce)
                .verifyComplete();

        verify(credentialOfferByNonceCache, times(1)).add(anyString(), any());
        verifyNoInteractions(oldNonceByIssuanceIdCache);
    }

    @Test
    void consumeCredentialOffer_ExistingNonce_ReturnsCredentialOfferData() {
        // Arrange
        String nonce = "test-nonce";
        CredentialOfferData credentialOfferData = CredentialOfferData.builder().build();
        doReturn(Mono.just(credentialOfferData)).when(credentialOfferByNonceCache).getAndDelete(nonce);

        // Act
        Mono<CredentialOfferData> result = credentialOfferCacheRepository.consumeCredentialOffer(nonce);

        // Assert
        StepVerifier.create(result)
                .expectNext(credentialOfferData)
                .verifyComplete();

        verify(credentialOfferByNonceCache, times(1)).getAndDelete(nonce);
    }

    @Test
    void consumeCredentialOffer_NonExistingNonce_ThrowsCredentialOfferNotFoundException() {
        // Arrange
        String nonce = "test-nonce";
        doReturn(Mono.<CredentialOfferData>error(new NoSuchElementException("Value is not present.")))
                .when(credentialOfferByNonceCache).getAndDelete(nonce);

        // Act
        Mono<CredentialOfferData> result = credentialOfferCacheRepository.consumeCredentialOffer(nonce);

        // Assert
        StepVerifier.create(result)
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining("CredentialOffer not found for nonce: " + nonce))
                .verify();

        verify(credentialOfferByNonceCache, times(1)).getAndDelete(nonce);
    }

    @Test
    void saveCredentialOffer_WhenCalledTwiceWithSameIssuanceId_PreviousNonceIsInvalidated() {
        // Arrange
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CacheStore<String> indexCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CredentialOfferCacheRepositoryImpl realRepository =
                new CredentialOfferCacheRepositoryImpl(realCache, indexCache);
        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-abc")
                .build();

        // Act
        String oldNonce = realRepository.saveCredentialOffer(offerData).block();
        realRepository.saveCredentialOffer(offerData).block();

        // Assert
        StepVerifier.create(realRepository.consumeCredentialOffer(oldNonce))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining(oldNonce))
                .verify();
    }

    @Test
    void consumeCredentialOffer_AfterRefreshWithSameIssuanceId_ReturnsCorrectData() {
        // Arrange
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CacheStore<String> indexCache = new CacheStore<>(5, TimeUnit.MINUTES);
        CredentialOfferCacheRepositoryImpl realRepository =
                new CredentialOfferCacheRepositoryImpl(realCache, indexCache);
        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-xyz")
                .build();

        // Act
        realRepository.saveCredentialOffer(offerData).block();
        String newNonce = realRepository.saveCredentialOffer(offerData).block();

        // Assert
        StepVerifier.create(realRepository.consumeCredentialOffer(newNonce))
                .expectNext(offerData)
                .verifyComplete();
    }

    @Test
    void consumeCredentialOffer_WhenTtlExpires_ThrowsCredentialOfferNotFoundException() throws InterruptedException {
        // Arrange
        CacheStore<CredentialOfferData> realCache = new CacheStore<>(50, TimeUnit.MILLISECONDS);
        CacheStore<String> indexCache = new CacheStore<>(50, TimeUnit.MILLISECONDS);
        CredentialOfferCacheRepositoryImpl realRepository =
                new CredentialOfferCacheRepositoryImpl(realCache, indexCache);
        CredentialOfferData offerData = CredentialOfferData.builder()
                .issuanceId("issuance-ttl")
                .build();
        String nonce = realRepository.saveCredentialOffer(offerData).block();

        // Act
        Thread.sleep(100);

        // Assert
        StepVerifier.create(realRepository.consumeCredentialOffer(nonce))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining(nonce))
                .verify();
    }
}
