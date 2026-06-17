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
            for (TenantEntry entry : tenants) {
                index.put(entry.id(), entry);
            }
            this.entries = Map.copyOf(index);
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
     * Returns the configured verifier base URL for the given tenant.
     *
     * @throws IllegalStateException if the tenant has no entry in the registry
     */
    public String getVerifierUrl(String tenantId) {
        TenantEntry entry = entries.get(tenantId);
        if (entry == null) {
            throw new IllegalStateException(
                    "No custom domain config found for tenant '" + tenantId + "'. " +
                    "Add it to the tenant custom domains file or check APP_TENANT_CUSTOM_DOMAINS_PATH.");
        }
        return entry.verifier();
    }

    private static void validate(List<TenantEntry> tenants) {
        for (TenantEntry entry : tenants) {
            if (entry.id() == null || entry.id().isBlank()) {
                throw new IllegalArgumentException("A tenant entry has a blank id");
            }
            validateUrl("issuer",   entry.id(), entry.issuer());
            validateUrl("verifier", entry.id(), entry.verifier());
            validateUrl("wallet",   entry.id(), entry.wallet());
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
            @JsonProperty("id")       String id,
            @JsonProperty("issuer")   String issuer,
            @JsonProperty("verifier") String verifier,
            @JsonProperty("wallet")   String wallet
    ) {}
}
