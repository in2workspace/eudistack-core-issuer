package es.in2.issuer.backend.shared.infrastructure.config.tenantconfig;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Loads the per-tenant custom domain registry from a YAML file at startup.
 *
 * <p>Used by {@link es.in2.issuer.backend.shared.domain.spi.UrlResolver} to resolve
 * the verifier public URL in non-canonical deployments (CloudFront, {@code X-Tenant}
 * header present) where the verifier URL cannot be derived from the request origin.
 *
 * <p>The registry is loaded once on startup and kept as an immutable {@link Map}.
 * A missing file is tolerated with a warning (valid for canonical-only deployments).
 * A malformed file causes a startup failure.
 */
@Slf4j
@Component
public class TenantCustomDomainsLoader {

    private final ResourceLoader resourceLoader;
    private final String configPath;
    private Map<String, TenantEntry> entries = Map.of();
    private Map<String, String> walletUrlByIssuerHost = Map.of();

    public TenantCustomDomainsLoader(
            ResourceLoader resourceLoader,
            @Value("${app.tenant-custom-domains.path:classpath:tenants-custom-domains.yaml}") String configPath
    ) {
        this.resourceLoader = resourceLoader;
        this.configPath = configPath;
    }

    @PostConstruct
    void load() {
        Resource resource = resourceLoader.getResource(configPath);
        if (!resource.exists()) {
            log.warn("Tenant custom domains file not found at '{}'. " +
                     "Non-canonical verifier URL resolution will fail at runtime.", configPath);
            return;
        }
        try (InputStream is = resource.getInputStream()) {
            ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
            TenantList data = yamlMapper.readValue(is, TenantList.class);
            List<TenantEntry> tenants = data.tenants() != null ? data.tenants() : List.of();
            validate(tenants);
            Map<String, TenantEntry> index = new HashMap<>();
            Map<String, String> walletIndex = new HashMap<>();
            for (TenantEntry entry : tenants) {
                TenantEntry previous = index.putIfAbsent(entry.id(), entry);
                if (previous != null) {
                    throw new IllegalArgumentException("Duplicate tenant id '" + entry.id() + "'");
                }
                String issuerHost = hostOf(entry.issuer());
                if (issuerHost != null && entry.wallet() != null) {
                    String prevWallet = walletIndex.putIfAbsent(issuerHost, entry.wallet());
                    if (prevWallet != null) {
                        throw new IllegalArgumentException("Duplicate issuer host '" + issuerHost + "'");
                    }
                }
            }
            this.entries = Map.copyOf(index);
            this.walletUrlByIssuerHost = Map.copyOf(walletIndex);
            log.info("Loaded {} tenant custom domain(s) from '{}'", entries.size(), configPath);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "Invalid tenant custom domains config at '" + configPath + "': " + e.getMessage(), e);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load tenant custom domains from '" + configPath + "'", e);
        }
    }

    /**
     * Returns the configured verifier base URLs for the given tenant.
     *
     * @throws IllegalStateException if the tenant has no entry in the registry
     */
    public List<String> getVerifierUrls(String tenantId) {
        TenantEntry entry = entries.get(tenantId);
        if (entry == null) {
            throw new IllegalStateException(
                    "No custom domain config found for tenant '" + tenantId + "'. " +
                    "Add it to the tenant custom domains file or check APP_TENANTS_CUSTOM_DOMAINS_PATH.");
        }
        return entry.verifiers();
    }

    /**
     * Returns the configured verifier base URLs for the given tenant, or
     * {@link Optional#empty()} if no entry exists for that tenant.
     * Use this instead of {@link #getVerifierUrls} when falling back to
     * origin-based resolution is acceptable (e.g. canonical deployments).
     */
    public Optional<List<String>> findVerifierUrls(String tenantId) {
        TenantEntry entry = entries.get(tenantId);
        return entry != null ? Optional.of(entry.verifiers()) : Optional.empty();
    }

    /**
     * Returns the configured wallet base URL for the entry whose {@code issuer}
     * URL has the given host, or {@link Optional#empty()} if no entry matches.
     *
     * <p>Used to build the credential-offer wallet deep-link. In non-canonical
     * deployments the wallet runs on a separate host (e.g.
     * {@code wallet.dome-marketplace.org}) that cannot be derived from the
     * issuer request origin, so it MUST be read from this registry, matched by
     * the host the request actually arrived through. In canonical (path-based)
     * deployments the host is absent from the registry and callers fall back to
     * origin-based resolution.
     */
    public Optional<String> findWalletUrlByIssuerHost(String issuerHost) {
        if (issuerHost == null || issuerHost.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(walletUrlByIssuerHost.get(issuerHost));
    }

    private static String hostOf(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        return URI.create(url).getHost();
    }

    private static void validate(List<TenantEntry> tenants) {
        for (TenantEntry entry : tenants) {
            if (entry.id() == null || entry.id().isBlank()) {
                throw new IllegalArgumentException("A tenant entry has a blank id");
            }
            validateUrl("issuer", entry.id(), entry.issuer());
            validateUrl("wallet", entry.id(), entry.wallet());
            validateVerifiers(entry.id(), entry.verifiers());
        }
    }

    private static void validateVerifiers(String tenantId, List<String> verifiers) {
        if (verifiers == null || verifiers.isEmpty()) {
            throw new IllegalArgumentException(
                    "Tenant '" + tenantId + "': field 'verifiers' must have at least one URL");
        }
        for (String url : verifiers) {
            validateUrl("verifiers", tenantId, url);
        }
    }

    private static void validateUrl(String field, String tenantId, String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException(
                    "Tenant '" + tenantId + "': field '" + field + "' is blank");
        }
        try {
            URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Tenant '" + tenantId + "': field '" + field + "' is not a valid URI: " + url, e);
        }
    }

    public record TenantList(
            @JsonProperty("tenants") List<TenantEntry> tenants
    ) {}

    public record TenantEntry(
            @JsonProperty("id")        String id,
            @JsonProperty("issuer")    String issuer,
            @JsonProperty("verifiers") List<String> verifiers,
            @JsonProperty("wallet")    String wallet
    ) {}
}
