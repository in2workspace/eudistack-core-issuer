package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import es.in2.issuer.backend.shared.domain.model.entities.TenantSigningConfig;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantSigningConfigRepository;
import es.in2.issuer.backend.signing.domain.exception.SigningConfigurationChangedException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.service.OwnKeySigningConfigLoader;
import es.in2.issuer.backend.signing.domain.util.SigningConfigScope;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.time.Duration;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
public class TenantSigningConfigServiceImpl implements TenantSigningConfigService {

    private static final String ACTIVE_STATUS = "active";

    private final TenantSigningConfigRepository repository;
    private final Cache<String, ActiveSigningConfig> configCache;
    private final ObjectMapper objectMapper;
    private final OwnKeySigningConfigLoader ownKeySigningConfigLoader;

    @Autowired
    public TenantSigningConfigServiceImpl(TenantSigningConfigRepository repository,
                                          ObjectMapper objectMapper,
                                          OwnKeySigningConfigLoader ownKeySigningConfigLoader,
                                          @Value("${issuer.signing.config-cache-ttl:5m}") Duration configCacheTtl) {
        this(repository, objectMapper, ownKeySigningConfigLoader, configCacheTtl, Ticker.systemTicker());
    }

    TenantSigningConfigServiceImpl(TenantSigningConfigRepository repository,
                                   ObjectMapper objectMapper,
                                   OwnKeySigningConfigLoader ownKeySigningConfigLoader,
                                   Duration configCacheTtl,
                                   Ticker ticker) {
        if (configCacheTtl == null || configCacheTtl.isZero() || configCacheTtl.isNegative()) {
            throw new IllegalArgumentException("issuer.signing.config-cache-ttl must be positive");
        }
        this.repository = repository;
        // EUD-251 design AD-5: during the TTL (5 min by default) an instance can keep using a replaced
        // or withdrawn configuration. Accepted deviation, see the design §16.
        this.configCache = Caffeine.newBuilder()
                .expireAfterWrite(configCacheTtl)
                .ticker(ticker)
                .maximumSize(50)
                .build();
        this.objectMapper = objectMapper;
        this.ownKeySigningConfigLoader = ownKeySigningConfigLoader;
    }

    @Override
    public Mono<ActiveSigningConfig> getActiveSigningConfig() {
        return Mono.deferContextual(ctx -> {
            String tenant = tenantOf(ctx);
            Optional<SigningConfigScope.Pins> pins = SigningConfigScope.current(ctx);

            Optional<ActiveSigningConfig> pinned = pins.flatMap(p -> p.get(tenant));
            if (pinned.isPresent()) {
                return Mono.just(pinned.get());
            }

            Mono<ActiveSigningConfig> config = cachedOrLoad(tenant);
            return pins.map(p -> config.map(c -> p.pinIfAbsent(tenant, c))).orElse(config);
        });
    }

    /**
     * Within a {@link SigningConfigScope}, a reload that finds another configuration than the one the
     * request already used fails with {@link SigningConfigurationChangedException}, so the scope runs the
     * request again instead of signing with a configuration its payload does not match.
     */
    @Override
    public Mono<ActiveSigningConfig> reloadActiveSigningConfig() {
        return Mono.deferContextual(ctx -> {
            String tenant = tenantOf(ctx);
            configCache.invalidate(tenant);

            Optional<ActiveSigningConfig> pinned = SigningConfigScope.current(ctx).flatMap(p -> p.get(tenant));
            if (pinned.isEmpty()) {
                return getActiveSigningConfig();
            }
            return cachedOrLoad(tenant)
                    .flatMap(fresh -> fresh.equals(pinned.get())
                            ? Mono.just(fresh)
                            : Mono.error(new SigningConfigurationChangedException()));
        });
    }

    private static String tenantOf(ContextView ctx) {
        return ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "unknown");
    }

    private Mono<ActiveSigningConfig> cachedOrLoad(String tenant) {
        ActiveSigningConfig cached = configCache.getIfPresent(tenant);
        if (cached != null) {
            return Mono.just(cached);
        }

        return repository.findFirstByStatusOrderByCreatedAtDesc(ACTIVE_STATUS)
                .flatMap(row -> toActiveSigningConfig(tenant, row))
                .doOnNext(config -> {
                    configCache.put(tenant, config);
                    log.debug("Loaded active signing config for '{}': modality {}", tenant, config.modality());
                });
    }

    private Mono<ActiveSigningConfig> toActiveSigningConfig(String tenant, TenantSigningConfig row) {
        return switch (modalityOf(tenant, row)) {
            case QTSP -> Mono.just(ActiveSigningConfig.qtsp(toRemoteSignatureDto(row)));
            // The certificate of an own key and the alias of its key are not in the database: they come from
            // the certificate infra publishes for the tenant.
            case OWN_KEY -> ownKeySigningConfigLoader.load(tenant).map(ActiveSigningConfig::ownKey);
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
