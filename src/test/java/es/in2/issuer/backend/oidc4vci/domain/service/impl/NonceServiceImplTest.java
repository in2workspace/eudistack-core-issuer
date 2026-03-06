package es.in2.issuer.backend.oidc4vci.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.NonceResponse;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.NONCE_CACHE_EXPIRY_SECONDS;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NonceServiceImplTest {

    @Mock
    private CacheStore<String> nonceCacheStore;

    @InjectMocks
    private NonceServiceImpl nonceService;

    @Test
    void issueNonce_shouldReturnNonceResponse() {
        when(nonceCacheStore.add(anyString(), anyString()))
                .thenAnswer(invocation -> Mono.just(invocation.getArgument(0, String.class)));

        StepVerifier.create(nonceService.issueNonce())
                .assertNext(response -> {
                    assert response instanceof NonceResponse;
                    assert response.cNonce() != null;
                    assert !response.cNonce().isBlank();
                    assert response.cNonceExpiresIn() == NONCE_CACHE_EXPIRY_SECONDS;
                })
                .verifyComplete();
    }
}
