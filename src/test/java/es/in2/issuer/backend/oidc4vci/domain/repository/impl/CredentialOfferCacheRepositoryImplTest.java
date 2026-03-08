package es.in2.issuer.backend.oidc4vci.domain.repository.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

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
}
