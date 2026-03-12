package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Loads and manages the trusted wallet providers list.
 * Analogous to the European LOTL for wallet attestation providers.
 */
@Slf4j
@Service
public class TrustedWalletProvidersService {

    private final ResourceLoader resourceLoader;
    private final String providersPath;
    private final Map<String, TrustedProvider> trustedProviders = new ConcurrentHashMap<>();

    public TrustedWalletProvidersService(
            ResourceLoader resourceLoader,
            @Value("${wallet-provider-trust.providers-path:classpath:trusted-wallet-providers.yaml}") String providersPath
    ) {
        this.resourceLoader = resourceLoader;
        this.providersPath = providersPath;
    }

    @PostConstruct
    public void loadProviders() {
        try {
            Resource resource = resourceLoader.getResource(providersPath);
            if (!resource.exists()) {
                log.warn("Trusted wallet providers file not found at: {}. No providers will be trusted.", providersPath);
                return;
            }

            ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
            try (InputStream is = resource.getInputStream()) {
                TrustedProvidersList list = yamlMapper.readValue(is, TrustedProvidersList.class);
                if (list.trustedWalletProviders() != null) {
                    for (TrustedProvider provider : list.trustedWalletProviders()) {
                        trustedProviders.put(provider.id(), provider);
                        log.info("Loaded trusted wallet provider: id={}, name={}", provider.id(), provider.name());
                    }
                }
            }
            log.info("Loaded {} trusted wallet provider(s)", trustedProviders.size());
        } catch (Exception e) {
            log.error("Failed to load trusted wallet providers from {}: {}", providersPath, e.getMessage(), e);
        }
    }

    public boolean isWalletProviderTrusted(String issuerId) {
        if (issuerId == null) return false;
        return trustedProviders.containsKey(issuerId);
    }

    public List<TrustedProvider> getAllTrustedProviders() {
        return Collections.unmodifiableList(List.copyOf(trustedProviders.values()));
    }

    public record TrustedProvidersList(
            @JsonProperty("trustedWalletProviders") List<TrustedProvider> trustedWalletProviders
    ) {}

    public record TrustedProvider(
            @JsonProperty("id") String id,
            @JsonProperty("name") String name,
            @JsonProperty("publicKeyPem") String publicKeyPem
    ) {}
}
