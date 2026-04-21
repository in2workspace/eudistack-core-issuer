package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
public class TenantCredentialProfileServiceImpl implements TenantCredentialProfileService {

    private static final Duration CACHE_TTL = Duration.ofMinutes(5);

    private final TenantCredentialProfileRepository repository;
    private final CredentialProfileRegistry registry;
    private final Cache<String, Set<String>> cache;

    public TenantCredentialProfileServiceImpl(
            TenantCredentialProfileRepository repository,
            CredentialProfileRegistry registry) {
        this.repository = repository;
        this.registry = registry;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(CACHE_TTL)
                .maximumSize(100)
                .build();
    }

    @Override
    public Mono<Set<String>> getEnabledConfigurationIds() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");
            Set<String> cached = cache.getIfPresent(tenant);
            if (cached != null) {
                return Mono.just(cached);
            }

            return repository.findAllByEnabledTrue()
                    .map(TenantCredentialProfile::credentialConfigurationId)
                    .collect(Collectors.toSet())
                    .doOnNext(ids -> {
                        cache.put(tenant, ids);
                        log.debug("Loaded {} enabled credential profiles for tenant '{}'", ids.size(), tenant);
                    });
        });
    }

    @Override
    public Mono<Map<String, CredentialProfile>> getAvailableProfiles() {
        return getEnabledConfigurationIds()
                .map(enabledIds -> {
                    Map<String, CredentialProfile> allProfiles = registry.getAllProfiles();
                    if (enabledIds.isEmpty()) {
                        return allProfiles;
                    }
                    return allProfiles.entrySet().stream()
                            .filter(entry -> enabledIds.contains(entry.getKey()))
                            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
                });
    }

    @Override
    public Mono<Boolean> isProfileAllowed(String credentialConfigurationId) {
        return getEnabledConfigurationIds()
                .map(enabledIds -> enabledIds.isEmpty() || enabledIds.contains(credentialConfigurationId));
    }

}
