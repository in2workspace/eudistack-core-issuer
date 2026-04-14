package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.AsyncCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.model.entities.TenantRegistry;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantRegistryRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Service
public class TenantRegistryServiceImpl implements TenantRegistryService {

    private static final String CACHE_KEY = "active_schemas";
    private static final Duration CACHE_TTL = Duration.ofMinutes(5);

    private final TenantRegistryRepository tenantRegistryRepository;
    private final AsyncCache<String, List<String>> cache;

    public TenantRegistryServiceImpl(TenantRegistryRepository tenantRegistryRepository) {
        this.tenantRegistryRepository = tenantRegistryRepository;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(CACHE_TTL)
                .buildAsync();
    }

    @Override
    public Mono<List<String>> getActiveTenantSchemas() {
        CompletableFuture<List<String>> cached = cache.getIfPresent(CACHE_KEY);
        if (cached != null) {
            return Mono.fromFuture(cached);
        }
        return tenantRegistryRepository.findAllByStatus("active")
                .map(TenantRegistry::schemaName)
                .collectList()
                .doOnNext(schemas -> {
                    log.debug("Loaded {} active tenant schemas from registry", schemas.size());
                    cache.put(CACHE_KEY, CompletableFuture.completedFuture(schemas));
                });
    }

}
