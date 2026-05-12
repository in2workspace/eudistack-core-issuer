package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantSigningConfigRepository;
import es.in2.issuer.backend.signing.domain.model.dto.RemoteSignatureDto;
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
    private final Cache<String, RemoteSignatureDto> signatureCache;

    public TenantSigningConfigServiceImpl(TenantSigningConfigRepository repository) {
        this.repository = repository;
        this.signatureCache = Caffeine.newBuilder()
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
                    });
        });
    }

    private RemoteSignatureDto toRemoteSignatureDto(TenantSigningConfig config) {
        JsonNode psc = config.providerSpecificConfig();
        return new RemoteSignatureDto(
                psc.path("url").asText(),
                psc.path("clientId").asText(),
                psc.path("clientSecret").asText(),
                psc.path("credentialId").asText(),
                psc.path("credentialPwd").asText(),
                psc.path("certCacheTtl").asText(null),
                psc.hasNonNull("signPath") ? psc.get("signPath").asText() : "sign-hash"
        );
    }

}
