package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantSigningConfigRepository;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.infrastructure.properties.SigningConfigCacheProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
public class TenantSigningConfigServiceImpl implements TenantSigningConfigService {

    private static final String ACTIVE_STATUS = "active";
    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {};

    private final TenantSigningConfigRepository repository;
    private final Cache<String, ActiveSigningConfig> configCache;
    private final ObjectMapper objectMapper;

    @Autowired
    public TenantSigningConfigServiceImpl(TenantSigningConfigRepository repository,
                                          ObjectMapper objectMapper,
                                          SigningConfigCacheProperties cacheProperties) {
        this(repository, objectMapper, cacheProperties, Ticker.systemTicker());
    }

    TenantSigningConfigServiceImpl(TenantSigningConfigRepository repository,
                                   ObjectMapper objectMapper,
                                   SigningConfigCacheProperties cacheProperties,
                                   Ticker ticker) {
        this.repository = repository;
        // EUD-251 design AD-5: during the TTL (5 min by default) an instance can keep using a replaced
        // or withdrawn configuration. Accepted deviation from AC-15 and EC-02, see the design §16.
        this.configCache = Caffeine.newBuilder()
                .expireAfterWrite(cacheProperties.configCacheTtl())
                .ticker(ticker)
                .maximumSize(50)
                .build();
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<ActiveSigningConfig> getActiveSigningConfig() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");

            ActiveSigningConfig cached = configCache.getIfPresent(tenant);
            if (cached != null) {
                return Mono.just(cached);
            }

            return repository.findFirstByStatusOrderByCreatedAtDesc(ACTIVE_STATUS)
                    .map(row -> toActiveSigningConfig(tenant, row))
                    .doOnNext(config -> {
                        configCache.put(tenant, config);
                        log.debug("Loaded active signing config for '{}': modality {}", tenant, config.modality());
                    });
        });
    }

    private ActiveSigningConfig toActiveSigningConfig(String tenant, TenantSigningConfig row) {
        return switch (modalityOf(tenant, row)) {
            case QTSP -> ActiveSigningConfig.qtsp(toRemoteSignatureDto(row));
            case OWN_KEY -> ActiveSigningConfig.ownKey(toOwnKeySigningConfig(tenant, row));
        };
    }

    private static SigningModality modalityOf(String tenant, TenantSigningConfig row) {
        if ("qtsp".equals(row.modality())) {
            return SigningModality.QTSP;
        }
        if ("own_key".equals(row.modality())) {
            return SigningModality.OWN_KEY;
        }
        log.error("Active signing config of tenant '{}' has an unknown modality", tenant);
        throw invalidConfiguration();
    }

    /**
     * A corrupt own-key row is reported as {@code NO_CONFIGURATION}: the tenant has no usable
     * configuration. It is not {@code KEY_UNUSABLE} (the key itself was never reached) nor
     * {@code CERTIFICATE_INVALID} (the certificate was never checked).
     */
    private OwnKeySigningConfig toOwnKeySigningConfig(String tenant, TenantSigningConfig row) {
        try {
            List<String> chain = row.ownKeyCertificateChain() == null
                    ? List.of()
                    : objectMapper.readValue(row.ownKeyCertificateChain(), STRING_LIST);
            return new OwnKeySigningConfig(
                    row.ownKeyKmsKeyRef(),
                    row.ownKeyAlgorithm(),
                    chain);
        } catch (IllegalArgumentException | JsonProcessingException e) {
            log.error("Active own-key signing config of tenant '{}' is invalid: {}",
                    tenant, e.getClass().getSimpleName());
            throw invalidConfiguration();
        }
    }

    private static SigningException invalidConfiguration() {
        return new SigningException(SigningFailureReason.NO_CONFIGURATION,
                "The active signing configuration of this tenant is invalid");
    }

    private RemoteSignatureDto toRemoteSignatureDto(TenantSigningConfig config) {
        try {
            JsonNode psc = objectMapper.readTree(config.providerSpecificConfig());
            String cscUrl = psc.path("url").asText();
            String authUrl = psc.hasNonNull("authUrl") ? psc.get("authUrl").asText() : cscUrl;
            return new RemoteSignatureDto(
                    config.provider(),
                    config.cscApiVersion(),
                    cscUrl,
                    authUrl,
                    psc.hasNonNull("signPath") ? psc.get("signPath").asText() : "sign-hash",
                    psc.path("credentialId").asText(),
                    psc.path("credentialPwd").asText(),
                    psc.path("certCacheTtl").asText(null),
                    psc.path("clientId").asText(),
                    psc.path("clientSecret").asText(),
                    psc.path("applicationName").asText(),
                    psc.path("qtspTenantId").asText(),
                    psc.path("appId").asText(),
                    psc.path("accessKey").asText(),
                    psc.path("managerId").asText()
            );
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
