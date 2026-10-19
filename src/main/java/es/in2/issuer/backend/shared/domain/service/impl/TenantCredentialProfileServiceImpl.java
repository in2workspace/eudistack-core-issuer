package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.CredentialConfigurationNotEnabledException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.Constants.SYSTEM_TENANT;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Service
public class TenantCredentialProfileServiceImpl implements TenantCredentialProfileService {

    private static final Duration CACHE_TTL = Duration.ofMinutes(5);

    private final TenantCredentialProfileRepository repository;
    private final CatalogEntryPort catalogEntryPort;
    private final CredentialProfileRegistry registry;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;
    private final TransactionalOperator transactionalOperator;
    private final Cache<String, Map<String, CatalogEntry>> cache;

    public TenantCredentialProfileServiceImpl(
            TenantCredentialProfileRepository repository,
            CatalogEntryPort catalogEntryPort,
            CredentialProfileRegistry registry,
            SchemaDeliveryCeiling schemaDeliveryCeiling,
            TransactionalOperator transactionalOperator) {
        this.repository = repository;
        this.catalogEntryPort = catalogEntryPort;
        this.registry = registry;
        this.schemaDeliveryCeiling = schemaDeliveryCeiling;
        this.transactionalOperator = transactionalOperator;
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(CACHE_TTL)
                .maximumSize(100)
                .build();
    }

    @Override
    public Mono<Set<String>> getEnabledConfigurationIds() {
        return getEnabledEntries().map(Map::keySet);
    }

    @Override
    public Mono<Map<String, CredentialProfile>> getAvailableProfiles() {
        return getEnabledConfigurationIds()
                .map(enabledIds -> registry.getAllProfiles().entrySet().stream()
                        .filter(entry -> enabledIds.contains(entry.getKey()))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));
    }

    @Override
    public Mono<Boolean> isProfileAllowed(String credentialConfigurationId) {
        return getEnabledConfigurationIds()
                .map(enabledIds -> enabledIds.contains(credentialConfigurationId));
    }

    @Override
    public Mono<Set<DeliveryMode>> findConfiguredDeliveryModes(String credentialConfigurationId) {
        return Mono.deferContextual(ctx -> {
            requireTenant(ctx);
            return getEnabledEntries()
                    .flatMap(entries -> entries.containsKey(credentialConfigurationId)
                            ? Mono.just(configuredModesOf(entries.get(credentialConfigurationId)))
                            : Mono.error(new CredentialConfigurationNotEnabledException(
                                    "Credential configuration id '" + credentialConfigurationId + "' is not enabled for this tenant")));
        });
    }

    @Override
    public Mono<CatalogEntry> findEnabledEntry(String credentialConfigurationId) {
        return getEnabledEntries().flatMap(entries -> Mono.justOrEmpty(entries.get(credentialConfigurationId)));
    }

    @Override
    public void invalidateCache(String tenant) {
        cache.invalidate(tenant);
    }

    @Override
    public Mono<List<CredentialCatalogEntryDto>> getCatalog() {
        return Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx);
            return getEnabledEntries()
                    .map(entries -> entries.values().stream()
                            .collect(Collectors.toMap(CatalogEntry::credentialConfigurationId,
                                    TenantCredentialProfileServiceImpl::configuredModesOf)))
                    .map(modesMap -> registry.getAllProfiles().entrySet().stream()
                            .map(entry -> toEntryDto(entry.getKey(), entry.getValue(), modesMap))
                            .sorted(Comparator.comparing(CredentialCatalogEntryDto::displayName))
                            .toList())
                    .flatMap(entries -> {
                        if (entries.stream().noneMatch(CredentialCatalogEntryDto::enabled)) {
                            return Mono.error(new CredentialCatalogNotConfiguredException(
                                    "No credential configuration enabled for tenant '" + tenant + "'"));
                        }
                        return Mono.just(entries);
                    });
        });
    }

    @Override
    public Mono<Void> updateCatalog(Set<String> enabledConfigurationIds, Map<String, Set<DeliveryMode>> deliveryModesByConfigurationId) {
        Mono<Void> validation = Mono.fromRunnable(() -> validateUpdateRequest(enabledConfigurationIds, deliveryModesByConfigurationId));

        return validation.then(Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx);
            Instant now = Instant.now();

            Mono<Void> write = enabledConfigurationIds.isEmpty()
                    ? repository.deleteAll()
                    : Flux.fromIterable(enabledConfigurationIds)
                            .concatMap(id -> repository.upsert(id, true, canonicalModesOrNull(id, deliveryModesByConfigurationId), now))
                            .then(repository.deleteAllByCredentialConfigurationIdNotIn(enabledConfigurationIds))
                            .then();

            return transactionalOperator.transactional(write)
                    .doOnSuccess(v -> {
                        cache.invalidate(tenant);
                        log.info("Credential catalog updated for tenant '{}': {} type(s) enabled",
                                tenant, enabledConfigurationIds.size());
                    });
        }));
    }

    private void validateUpdateRequest(Set<String> enabledConfigurationIds, Map<String, Set<DeliveryMode>> deliveryModesByConfigurationId) {
        validateKnownToRegistry(enabledConfigurationIds);

        Set<String> notEnabled = deliveryModesByConfigurationId.keySet().stream()
                .filter(id -> !enabledConfigurationIds.contains(id))
                .collect(Collectors.toSet());
        if (!notEnabled.isEmpty()) {
            throw new InvalidDeliveryConfigException(
                    "Delivery modes declared for credential configuration id(s) not enabled in this request: " + notEnabled);
        }

        validateWithinCeiling(deliveryModesByConfigurationId);
    }

    private void validateKnownToRegistry(Set<String> credentialConfigurationIds) {
        Set<String> knownIds = registry.getAllProfiles().keySet();
        Set<String> unknown = credentialConfigurationIds.stream()
                .filter(id -> !knownIds.contains(id))
                .collect(Collectors.toSet());
        if (!unknown.isEmpty()) {
            throw new UnknownCredentialConfigurationException(
                    "Unknown credential configuration id(s): " + unknown);
        }
    }

    private void validateWithinCeiling(Map<String, Set<DeliveryMode>> deliveryModesByConfigurationId) {
        deliveryModesByConfigurationId.forEach(schemaDeliveryCeiling::validateWithinCeiling);
    }

    private String canonicalModesOrNull(String credentialConfigurationId, Map<String, Set<DeliveryMode>> deliveryModesByConfigurationId) {
        Set<DeliveryMode> declared = deliveryModesByConfigurationId.get(credentialConfigurationId);
        return declared == null ? null : DeliveryMode.toCanonicalCsv(declared);
    }

    private CredentialCatalogEntryDto toEntryDto(String credentialConfigurationId, CredentialProfile profile, Map<String, Set<DeliveryMode>> modesMap) {
        Set<DeliveryMode> ceiling = schemaDeliveryCeiling.resolveEligibleModes(credentialConfigurationId);
        Set<DeliveryMode> stored = modesMap.getOrDefault(credentialConfigurationId, Set.of());
        Set<DeliveryMode> eligible = stored.isEmpty()
                ? ceiling
                : stored.stream().filter(ceiling::contains).collect(Collectors.toSet());

        return new CredentialCatalogEntryDto(
                credentialConfigurationId,
                resolveDisplayName(profile),
                modesMap.containsKey(credentialConfigurationId),
                sortedValues(eligible),
                sortedValues(ceiling));
    }

    /**
     * Loads (or reads from cache) the per-tenant map of <em>enabled</em> catalog entries by
     * credential_configuration_id; {@code keySet()} is exactly the enabled ids, which the OID4VCI
     * metadata, {@code RequireCredentialProfileAllowedForTenantRule} and
     * {@code DeliveryEligibilityResolver} rely on. A disabled entry is never loaded, so it cannot be
     * issued nor advertised.
     */
    private Mono<Map<String, CatalogEntry>> getEnabledEntries() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SYSTEM_TENANT);
            Map<String, CatalogEntry> cached = cache.getIfPresent(tenant);
            if (cached != null) {
                return Mono.just(cached);
            }

            return catalogEntryPort.findAllByEnabled(true)
                    .collect(Collectors.toMap(CatalogEntry::credentialConfigurationId, entry -> entry))
                    .map(Map::copyOf)
                    .doOnNext(entries -> {
                        cache.put(tenant, entries);
                        log.debug("Loaded {} enabled catalog entries for tenant '{}'", entries.size(), tenant);
                    });
        });
    }

    /**
     * The delivery modes the tenant configured. Empty means "not filled yet" (D13), the sentinel that
     * callers resolve to the schema ceiling (AD-8): an enabled entry can never hold an explicit empty
     * list (D14), so an empty list is not read as one.
     */
    private static Set<DeliveryMode> configuredModesOf(CatalogEntry entry) {
        return entry.deliveryModes() == null ? Set.of() : entry.deliveryModes();
    }

    private static List<String> sortedValues(Set<DeliveryMode> modes) {
        return modes.stream().map(m -> m.value).sorted().toList();
    }

    /**
     * Resolves the tenant from the reactive context, rejecting when it is absent.
     * The admin catalog paths must never fall back to a default schema (unlike the
     * read side, which tolerates a missing tenant for public/system flows).
     */
    private String requireTenant(ContextView ctx) {
        String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
        if (tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tenant context not resolved");
        }
        return tenant;
    }

    private String resolveDisplayName(CredentialProfile profile) {
        CredentialProfile.CredentialMetadata metadata = profile.credentialMetadata();
        if (metadata != null && metadata.display() != null && !metadata.display().isEmpty()) {
            String name = metadata.display().getFirst().name();
            if (name != null && !name.isBlank()) {
                return name;
            }
        }
        return profile.credentialConfigurationId();
    }

}
