package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantSigningConfigRepository;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
import es.in2.issuer.backend.signing.infrastructure.config.RuntimeSigningConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
public class TenantSigningConfigServiceImpl implements TenantSigningConfigService {

    private static final Duration CACHE_TTL = Duration.ofMinutes(5);

    private final TenantSigningConfigRepository repository;
    private final RuntimeSigningConfig globalDefault;
    private final Cache<String, RemoteSignatureDto> signatureCache;
    private final Cache<String, String> providerCache;

    public TenantSigningConfigServiceImpl(
            TenantSigningConfigRepository repository,
            RuntimeSigningConfig globalDefault) {
        this.repository = repository;
        this.globalDefault = globalDefault;
        this.signatureCache = Caffeine.newBuilder()
                .expireAfterWrite(CACHE_TTL)
                .maximumSize(50)
                .build();
        this.providerCache = Caffeine.newBuilder()
                .expireAfterWrite(CACHE_TTL)
                .maximumSize(50)
                .build();
    }

    @Override
    public Mono<RemoteSignatureDto> getRemoteSignature() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");

            RemoteSignatureDto cached = signatureCache.getIfPresent(tenant);
            if (cached != null) {
                return Mono.just(cached);
            }

            return repository.findFirstByOrderByCreatedAtDesc()
                    .map(this::toRemoteSignatureDto)
                    .doOnNext(dto -> {
                        signatureCache.put(tenant, dto);
                        log.debug("Loaded tenant signing config for '{}': provider at {}", tenant, dto.url());
                    })
                    .switchIfEmpty(Mono.defer(() -> {
                        log.debug("No signing config for tenant '{}', using global default", tenant);
                        RemoteSignatureDto defaultDto = globalDefault.getRemoteSignature();
                        return defaultDto != null ? Mono.just(defaultDto) : Mono.empty();
                    }));
        });
    }

    @Override
    public Mono<String> getProvider() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");

            String cached = providerCache.getIfPresent(tenant);
            if (cached != null) {
                return Mono.just(cached);
            }

            return repository.findFirstByOrderByCreatedAtDesc()
                    .map(TenantSigningConfig::provider)
                    .doOnNext(provider -> providerCache.put(tenant, provider))
                    .switchIfEmpty(Mono.just(globalDefault.getProvider()));
        });
    }

    private RemoteSignatureDto toRemoteSignatureDto(TenantSigningConfig config) {
        return new RemoteSignatureDto(
                config.remoteUrl(),
                config.remoteClientId(),
                config.remoteClientSecret(),
                config.remoteCredentialId(),
                config.remoteCredentialPwd(),
                config.remoteCertCacheTtl(),
                config.remoteSignPath() != null ? config.remoteSignPath() : "sign-hash"
        );
    }

}
