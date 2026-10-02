package es.in2.issuer.backend.shared.infrastructure.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

import static es.in2.issuer.backend.shared.domain.util.Constants.CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME;
import static es.in2.issuer.backend.shared.domain.util.Constants.CREDENTIAL_OFFER_EXPIRED_RETENTION_MINUTES;
import static es.in2.issuer.backend.shared.domain.util.Constants.VERIFIABLE_CREDENTIAL_JWT_CACHE_EXPIRATION_TIME;

@Configuration
@RequiredArgsConstructor
public class CacheConfig {

    public long getCacheLifetimeForCredentialOffer() {
        return CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME;
    }

    /**
     * Physical lifetime (minutes) of a credential offer in the transient store: its logical
     * lifetime plus the retention window during which an expired or consumed offer is still
     * recognised (410 Gone) rather than reported as unknown (404 Not Found).
     */
    public long getCacheRetentionForCredentialOffer() {
        return CREDENTIAL_OFFER_CACHE_EXPIRATION_TIME + CREDENTIAL_OFFER_EXPIRED_RETENTION_MINUTES;
    }

    public long getCacheLifetimeForVerifiableCredential() {
        return VERIFIABLE_CREDENTIAL_JWT_CACHE_EXPIRATION_TIME;
    }
}
