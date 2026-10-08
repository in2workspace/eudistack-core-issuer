package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import es.in2.issuer.backend.oidc4vci.domain.exception.CredentialOfferNoLongerAvailableException;
import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialOfferCacheRepositoryImplTest {

    private static final Instant NOW = Instant.parse("2026-09-30T10:00:00Z");
    private static final String NONCE = "testNonce";

    @Mock
    private TransientStore<CredentialOfferData> cacheStore;

    private CredentialOfferCacheRepositoryImpl repository;

    @BeforeEach
    void setUp() {
        repository = new CredentialOfferCacheRepositoryImpl(cacheStore, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void CredentialOfferCacheRepository_saveCredentialOffer_stampsTenMinuteExpiry() {
        when(cacheStore.add(anyString(), any())).thenReturn(Mono.just(NONCE));

        StepVerifier.create(repository.saveCredentialOffer(CredentialOfferData.builder().txCode("1234").build()))
                .expectNext(NONCE)
                .verifyComplete();

        ArgumentCaptor<CredentialOfferData> stored = ArgumentCaptor.forClass(CredentialOfferData.class);
        verify(cacheStore).add(anyString(), stored.capture());
        assertThat(stored.getValue())
                .isEqualTo(CredentialOfferData.builder()
                        .txCode("1234")
                        .expiresAt(NOW.plus(Duration.ofMinutes(10)))
                        .consumed(false)
                        .build());
    }

    @Test
    void CredentialOfferCacheRepository_findCredentialOfferById_validOfferIsReturnedAndMarkedConsumed() {
        CredentialOfferData valid = CredentialOfferData.builder().expiresAt(NOW.plusSeconds(60)).build();
        when(cacheStore.get(NONCE)).thenReturn(Mono.just(valid));
        when(cacheStore.add(eq(NONCE), any())).thenReturn(Mono.just(NONCE));

        StepVerifier.create(repository.findCredentialOfferById(NONCE))
                .expectNext(valid)
                .verifyComplete();

        verify(cacheStore).add(NONCE, valid.markConsumed());
        verify(cacheStore, never()).delete(anyString());
    }

    @Test
    void CredentialOfferCacheRepository_findCredentialOfferById_unknownNonceIsNotFound() {
        when(cacheStore.get(NONCE)).thenReturn(Mono.empty());

        StepVerifier.create(repository.findCredentialOfferById(NONCE))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(CredentialOfferNotFoundException.class)
                        .hasMessageContaining("CredentialOffer not found for nonce: " + NONCE))
                .verify();

        verify(cacheStore, never()).add(anyString(), any());
    }

    @Test
    void CredentialOfferCacheRepository_findCredentialOfferById_expiredOfferIsNoLongerAvailable() {
        CredentialOfferData expired = CredentialOfferData.builder().expiresAt(NOW.minusSeconds(1)).build();
        when(cacheStore.get(NONCE)).thenReturn(Mono.just(expired));

        StepVerifier.create(repository.findCredentialOfferById(NONCE))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(CredentialOfferNoLongerAvailableException.class)
                        .hasMessage("The credential offer has expired."))
                .verify();

        verify(cacheStore, never()).add(anyString(), any());
    }

    @Test
    void CredentialOfferCacheRepository_findCredentialOfferById_consumedOfferIsNoLongerAvailable() {
        CredentialOfferData consumed = CredentialOfferData.builder()
                .expiresAt(NOW.plusSeconds(60))
                .consumed(true)
                .build();
        when(cacheStore.get(NONCE)).thenReturn(Mono.just(consumed));

        StepVerifier.create(repository.findCredentialOfferById(NONCE))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(CredentialOfferNoLongerAvailableException.class)
                        .hasMessage("The credential offer has already been used."))
                .verify();

        verify(cacheStore, never()).add(anyString(), any());
    }
}