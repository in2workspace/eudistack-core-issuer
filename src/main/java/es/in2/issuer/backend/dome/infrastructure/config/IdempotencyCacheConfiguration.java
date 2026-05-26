package es.in2.issuer.backend.dome.infrastructure.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.dome.domain.model.sync.IdempotencyCacheKey;
import es.in2.issuer.backend.dome.domain.model.sync.SyncCredentialsResult;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Configuration class for the DOME auto-recovery idempotency cache.
 */
@Configuration
public class IdempotencyCacheConfiguration {
    @Bean
    public Cache<IdempotencyCacheKey, SyncCredentialsResult> idempotencyCache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(5))
                .maximumSize(10_000)
                .build();
    }
}