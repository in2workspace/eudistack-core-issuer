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

import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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
        // Arrange
        String issuanceId = "test-issuance-id";
        CredentialOfferData credentialOfferData = CredentialOfferData.builder().build();

        when(cacheStore.add(eq(issuanceId), eq(credentialOfferData))).thenReturn(Mono.just(issuanceId));

        // Act & Assert
        StepVerifier.create(service.saveCredentialOffer(issuanceId, credentialOfferData))
                .expectNext(issuanceId)
                .verifyComplete();

        verify(cacheStore, times(1)).add(eq(issuanceId), eq(credentialOfferData));
    }

    @Test
    void SaveCredentialOffer_CalledTwiceWithSameIssuanceId_OverwritesPreviousEntry() {
        // Arrange
        String issuanceId = "test-issuance-id";
        CredentialOfferData firstOffer  = CredentialOfferData.builder().build();
        CredentialOfferData secondOffer = CredentialOfferData.builder().build();

        when(cacheStore.add(eq(issuanceId), any())).thenReturn(Mono.just(issuanceId));

        // Act
        service.saveCredentialOffer(issuanceId, firstOffer).block();
        service.saveCredentialOffer(issuanceId, secondOffer).block();

        // Assert
        verify(cacheStore, times(2)).add(eq(issuanceId), any());
    }

    @Test
    void testFindCredentialOfferById() {
        // Arrange
        String nonce = "testNonce";
        CredentialOfferData credentialOfferData = CredentialOfferData.builder().build();

        when(cacheStore.get(nonce)).thenReturn(Mono.just(credentialOfferData));
        when(cacheStore.delete(nonce)).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(service.findCredentialOfferById(nonce))
                .expectNextMatches(retrievedOffer -> retrievedOffer.equals(credentialOfferData))
                .verifyComplete();

        verify(cacheStore, times(1)).delete(nonce);
    }

    @Test
    void testFindCredentialOfferByIdNotFound() {
        // Arrange
        String nonce = "testNonce";
        when(cacheStore.get(nonce)).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(service.findCredentialOfferById(nonce))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining("CredentialOffer not found for nonce: " + nonce))
                .verify();

        verify(cacheStore, never()).delete(anyString());
    }

    // ─── QR expiration scenarios ──────────────────────────────────────────────

    @Test
    void FindCredentialOfferById_BothQrsActiveAfterRefresh_OnlyNewQrDataIsAccessible() {
        // Arrange
        CredentialOfferCacheRepositoryImpl repository = new CredentialOfferCacheRepositoryImpl(
                new CacheStore<>(10_000L, TimeUnit.MILLISECONDS));
        String issuanceId = "issuance-scenario-1";
        CredentialOfferData oldOffer = CredentialOfferData.builder().credentialEmail("old@test.com").build();
        CredentialOfferData newOffer = CredentialOfferData.builder().credentialEmail("new@test.com").build();

        // Act
        repository.saveCredentialOffer(issuanceId, oldOffer).block();
        repository.saveCredentialOffer(issuanceId, newOffer).block();

        // Assert
        StepVerifier.create(repository.findCredentialOfferById(issuanceId))
                .assertNext(result -> assertThat(result.credentialEmail())
                        .as("After refresh, only new offer data must be returned")
                        .isEqualTo("new@test.com"))
                .verifyComplete();
    }

    @Test
    void FindCredentialOfferById_OldQrExpiredThenNewQrSaved_NewQrDataIsAccessible() {
        // Arrange
        String issuanceId = "issuance-scenario-2";
        CredentialOfferData newOffer = CredentialOfferData.builder().credentialEmail("new@test.com").build();

        when(cacheStore.add(eq(issuanceId), eq(newOffer))).thenReturn(Mono.just(issuanceId));
        when(cacheStore.get(issuanceId)).thenReturn(Mono.just(newOffer));
        when(cacheStore.delete(issuanceId)).thenReturn(Mono.empty());

        // Act
        service.saveCredentialOffer(issuanceId, newOffer).block();

        // Assert
        StepVerifier.create(service.findCredentialOfferById(issuanceId))
                .assertNext(result -> assertThat(result.credentialEmail())
                        .as("After old expiry + refresh, new offer must be accessible")
                        .isEqualTo("new@test.com"))
                .verifyComplete();
    }

    @Test
    void FindCredentialOfferById_NewQrAlsoExpired_ThrowsCredentialOfferNotFoundException() {
        // Arrange
        String issuanceId = "issuance-scenario-3";

        when(cacheStore.get(issuanceId))
                .thenReturn(Mono.error(new NoSuchElementException("Value is not present.")));

        // Act & Assert
        StepVerifier.create(service.findCredentialOfferById(issuanceId))
                .expectErrorSatisfies(throwable -> assertThat(throwable)
                        .as("Expired QR must throw CredentialOfferNotFoundException")
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining(issuanceId))
                .verify();

        verify(cacheStore, never()).delete(anyString());
    }
}
