package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.exception.TenantConfigMissingException;
import es.in2.issuer.backend.shared.domain.model.entities.TenantConfig;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantConfigRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
public class TenantConfigServiceImpl implements TenantConfigService {

    private static final Duration CACHE_TTL = Duration.ofMinutes(5);

    private final TenantConfigRepository tenantConfigRepository;
    private final Cache<String, String> cache;

    public TenantConfigServiceImpl(TenantConfigRepository tenantConfigRepository) {
        this.tenantConfigRepository = tenantConfigRepository;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(CACHE_TTL)
                .maximumSize(500)
                .build();
    }

    @Override
    public Mono<String> getString(String key) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");
            String cacheKey = tenant + ":" + key;

            String cached = cache.getIfPresent(cacheKey);
            if (cached != null) {
                return Mono.just(cached);
            }

            return tenantConfigRepository.findByConfigKey(key)
                    .map(TenantConfig::configValue)
                    .doOnNext(value -> {
                        cache.put(cacheKey, value);
                        log.trace("Tenant config '{}'.'{}' = '{}'", tenant, key, value);
                    });
        });
    }

    @Override
    public Mono<String> getStringOrDefault(String key, String defaultValue) {
        return getString(key)
                .defaultIfEmpty(defaultValue);
    }

    @Override
    public Mono<String> getStringOrThrow(String key) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");
            return getString(key)
                    .switchIfEmpty(Mono.error(new TenantConfigMissingException(tenant, key)));
        });
    }

}
