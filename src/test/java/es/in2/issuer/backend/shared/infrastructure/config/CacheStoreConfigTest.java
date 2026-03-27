package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.dto.IssuanceIdAndTxCode;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CacheStoreConfigTest {

    @Mock
    private CacheConfig cacheConfig;

    private CacheStoreConfig cacheStoreConfig;

    @BeforeEach
    void setUp() {
        cacheStoreConfig = new CacheStoreConfig(cacheConfig);
    }

    @Test
    void testCacheStoreDefault() {
        TransientStore<String> stringCacheStore = cacheStoreConfig.cacheStoreDefault();
        assertNotNull(stringCacheStore);
    }

    @Test
    void testCacheStoreForTransactionCode() {
        TransientStore<String> cacheStoreForTransactionCode = cacheStoreConfig.cacheStoreForTransactionCode();
        assertNotNull(cacheStoreForTransactionCode);
    }

    @Test
    void testCacheStoreForCTransactionCode() {
        TransientStore<String> cacheStoreForTransactionCode = cacheStoreConfig.cacheStoreForCTransactionCode();
        assertNotNull(cacheStoreForTransactionCode);
    }

    @Test
    void testCredentialOfferByNonceCache() {
        long cacheLifetime = 60;
        when(cacheConfig.getCacheLifetimeForCredentialOffer()).thenReturn(cacheLifetime);

        TransientStore<CredentialOfferData> customCredentialOfferCacheStore = cacheStoreConfig.credentialOfferByNonceCache();
        assertNotNull(customCredentialOfferCacheStore);
    }

    @Test
    void testCacheStoreForCredentialIdAndTxCodeByPreAuthorizedCodeCacheStore() {
        TransientStore<IssuanceIdAndTxCode> customCredentialOfferCacheStore =
                cacheStoreConfig.issuanceIdAndTxCodeByPreAuthorizedCodeCacheStore();
        assertNotNull(customCredentialOfferCacheStore);
    }
}