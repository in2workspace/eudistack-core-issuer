package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.oidc4vci.domain.model.AuthorizationCodeData;
import es.in2.issuer.backend.oidc4vci.domain.model.PushedAuthorizationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceIdAndRefreshToken;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceIdAndTxCode;
import es.in2.issuer.backend.shared.domain.model.dto.VerifiableCredentialJWT;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.shared.infrastructure.repository.CacheStore;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

import static es.in2.issuer.backend.oidc4vci.domain.util.Constants.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Configuration
@RequiredArgsConstructor
public class CacheStoreConfig {

    private final CacheConfig cacheConfig;

    @Bean
    public TransientStore<String> cacheStoreDefault() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public TransientStore<String> cacheStoreForTransactionCode() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }
    @Bean
    public TransientStore<String> cacheStoreForCTransactionCode() {
        return new CacheStore<>(10, TimeUnit.MINUTES);
    }

    @Bean
    public TransientStore<VerifiableCredentialJWT> cacheStoreForVerifiableCredentialJwt() {
        return new CacheStore<>(cacheConfig.getCacheLifetimeForVerifiableCredential(), TimeUnit.MINUTES);
    }

    @Bean
    public TransientStore<CredentialOfferData> cacheStoreForCredentialOffer() {
        return new CacheStore<>(cacheConfig.getCacheLifetimeForCredentialOffer(), TimeUnit.MINUTES);
    }

    @Bean
    public TransientStore<IssuanceIdAndTxCode> issuanceIdAndTxCodeByPreAuthorizedCodeCacheStore() {
        return new CacheStore<>(PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES, TimeUnit.MINUTES);
    }

    @Bean
    public TransientStore<IssuanceIdAndRefreshToken> refreshTokenCacheStore() {
        return new CacheStore<>(REFRESH_TOKEN_EXPIRATION, REFRESH_TOKEN_EXPIRATION_TIME_UNIT);
    }

    @Bean
    public TransientStore<PushedAuthorizationRequest> parCacheStore() {
        return new CacheStore<>(PAR_CACHE_EXPIRY_SECONDS, TimeUnit.SECONDS);
    }

    @Bean
    public TransientStore<AuthorizationCodeData> authorizationCodeCacheStore() {
        return new CacheStore<>(AUTHORIZATION_CODE_CACHE_EXPIRY_SECONDS, TimeUnit.SECONDS);
    }

    @Bean
    public TransientStore<String> nonceCacheStore() {
        return new CacheStore<>(NONCE_CACHE_EXPIRY_SECONDS, TimeUnit.SECONDS);
    }

    @Bean
    public TransientStore<String> notificationCacheStore() {
        return new CacheStore<>(NOTIFICATION_CACHE_EXPIRY_HOURS, TimeUnit.HOURS);
    }

    @Bean
    public TransientStore<String> enrichmentCacheStore() {
        return new CacheStore<>(NOTIFICATION_CACHE_EXPIRY_HOURS, TimeUnit.HOURS);
    }

    @Bean
    public TransientStore<String> issuerStateCacheStore() {
        return new CacheStore<>(PRE_AUTH_CODE_EXPIRY_DURATION_MINUTES, TimeUnit.MINUTES);
    }
}
