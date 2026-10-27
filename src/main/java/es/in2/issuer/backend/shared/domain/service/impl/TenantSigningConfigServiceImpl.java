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
import es.in2.issuer.backend.signing.domain.exception.SigningConfigurationChangedException;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.spi.KmsSigningPort;
import es.in2.issuer.backend.signing.domain.util.SigningConfigScope;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
public class TenantSigningConfigServiceImpl implements TenantSigningConfigService {

    private static final String ACTIVE_STATUS = "active";
    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {};

    private final TenantSigningConfigRepository repository;
    private final Cache<String, ActiveSigningConfig> configCache;
    private final ObjectMapper objectMapper;
    /** The port exists only when {@code issuer.signing.kms.enabled=true}. */
    private final ObjectProvider<KmsSigningPort> kmsSigningPort;

    @Autowired
    public TenantSigningConfigServiceImpl(TenantSigningConfigRepository repository,
                                          ObjectMapper objectMapper,
                                          @Value("${issuer.signing.config-cache-ttl:5m}") Duration configCacheTtl,
                                          ObjectProvider<KmsSigningPort> kmsSigningPort) {
        this(repository, objectMapper, configCacheTtl, kmsSigningPort, Ticker.systemTicker());
    }

    TenantSigningConfigServiceImpl(TenantSigningConfigRepository repository,
                                   ObjectMapper objectMapper,
                                   Duration configCacheTtl,
                                   ObjectProvider<KmsSigningPort> kmsSigningPort,
                                   Ticker ticker) {
        if (configCacheTtl == null || configCacheTtl.isZero() || configCacheTtl.isNegative()) {
            throw new IllegalArgumentException("issuer.signing.config-cache-ttl must be positive");
        }
        this.repository = repository;
        // EUD-251 design AD-5: during the TTL (5 min by default) an instance can keep using a replaced
        // or withdrawn configuration. Accepted deviation from AC-15 and EC-02, see the design §16.
        this.configCache = Caffeine.newBuilder()
                .expireAfterWrite(configCacheTtl)
                .ticker(ticker)
                .maximumSize(50)
                .build();
        this.objectMapper = objectMapper;
        this.kmsSigningPort = kmsSigningPort;
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
     * request again instead of signing with a configuration its payload does not match (EUD-289 M4).
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
            case OWN_KEY -> withKeyTenantTag(toOwnKeySigningConfig(tenant, row)).map(ActiveSigningConfig::ownKey);
        };
    }

    /**
     * Reads the {@code Tenant} tag of the KMS key once, when the configuration is loaded, so the cache
     * keeps it with the configuration and signing does not ask KMS for it. If the tags cannot be read
     * the load fails with the reason of the KMS failure and nothing is cached. A key without the tag
     * is loaded with no tag: {@code KmsOwnKeySigningProvider} refuses to sign with it. When KMS signing
     * is not enabled on this issuer there is nothing to read; the provider reports that case itself.
     */
    private Mono<OwnKeySigningConfig> withKeyTenantTag(OwnKeySigningConfig config) {
        KmsSigningPort port = kmsSigningPort.getIfAvailable();
        if (port == null) {
            return Mono.just(config);
        }
        return port.findTenantTag(config.kmsKeyRef())
                .map(config::withKeyTenantTag)
                .defaultIfEmpty(config);
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
