package es.in2.issuer.backend.shared.domain.service.impl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException;
import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.CredentialConfigurationNotEnabledException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.UnsupportedBindingTypeException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.BindingType;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.CatalogEntryFiller;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Comparator;
import java.util.HashMap;
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

    /** A concurrent write to the same entry makes one of two alias writes retry; a handful is plenty. */
    private static final int MAX_CONCURRENT_WRITE_RETRIES = 3;

    private final CatalogEntryPort catalogEntryPort;
    private final CatalogEntryFiller catalogEntryFiller;
    private final CredentialProfileRegistry registry;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;
    private final TransactionalOperator transactionalOperator;
    private final Cache<String, Map<String, CatalogEntry>> cache;

    public TenantCredentialProfileServiceImpl(
            CatalogEntryPort catalogEntryPort,
            CatalogEntryFiller catalogEntryFiller,
            CredentialProfileRegistry registry,
            SchemaDeliveryCeiling schemaDeliveryCeiling,
            TransactionalOperator transactionalOperator) {
        this.catalogEntryPort = catalogEntryPort;
        this.catalogEntryFiller = catalogEntryFiller;
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

            // Re-run from the read when another write got to an entry first.
            Mono<Void> write = transactionalOperator.transactional(
                            Mono.defer(() -> replaceEnabledSet(enabledConfigurationIds, deliveryModesByConfigurationId)))
                    .retryWhen(Retry.max(MAX_CONCURRENT_WRITE_RETRIES)
                            .filter(ConcurrentEntryChange.class::isInstance));

            return write.doOnSuccess(v -> {
                cache.invalidate(tenant);
                log.info("Credential catalog updated for tenant '{}': {} type(s) enabled",
                        tenant, enabledConfigurationIds.size());
            });
        }));
    }

    /**
     * What the deprecated alias does, now on the entries of the attestation catalog (EUD-266, D5): the
     * listed types are enabled and the rest are <em>disabled</em>, never deleted, so what the tenant
     * configured on them (validity, subject, search identifiers, modes) survives. Only entries that change
     * are written, each with its version bumped; applying the same set twice writes nothing the second time.
     *
     * <p>A listed type keeps its stored delivery modes unless the request declares some (EC-01), and an
     * entry that was saved with none (possible only for a disabled one) reopens to the schema ceiling,
     * as it did before entries could hold an explicit empty list. A type without an entry gets one, with the
     * values of its type file. An entry not completed yet is completed in the same write (D13).
     */
    private Mono<Void> replaceEnabledSet(Set<String> enabledConfigurationIds,
                                         Map<String, Set<DeliveryMode>> deliveryModesByConfigurationId) {
        return catalogEntryPort.findAll().collectList()
                .flatMapMany(stored -> {
                    Map<String, CatalogEntry> byId = new HashMap<>();
                    stored.forEach(entry -> byId.put(entry.credentialConfigurationId(), entry));
                    Flux<Void> enable = Flux.fromIterable(enabledConfigurationIds)
                            .concatMap(id -> enable(byId.get(id), id, deliveryModesByConfigurationId.get(id)));
                    Flux<Void> disable = Flux.fromIterable(stored)
                            .filter(entry -> entry.enabled() && !enabledConfigurationIds.contains(entry.credentialConfigurationId()))
                            .concatMap(this::disable);
                    return enable.concatWith(disable);
                })
                .then();
    }

    private Mono<Void> enable(CatalogEntry stored, String credentialConfigurationId, Set<DeliveryMode> declaredModes) {
        if (stored == null) {
            return insertEnabled(credentialConfigurationId, declaredModes);
        }
        Set<DeliveryMode> modes = declaredModes != null ? declaredModes : storedOrCeilingModes(stored);
        CatalogEntry target = catalogEntryFiller.fill(stored).withEnabled(true).withDeliveryModes(modes);
        return target.equals(stored) ? Mono.empty() : write(stored, target);
    }

    private Mono<Void> disable(CatalogEntry stored) {
        return write(stored, catalogEntryFiller.fill(stored).withEnabled(false));
    }

    /** A new entry for a type that had none: its type file's values, and the ceiling when no modes are declared. */
    private Mono<Void> insertEnabled(String credentialConfigurationId, Set<DeliveryMode> declaredModes) {
        if (registry.bindingTypeOf(credentialConfigurationId) == BindingType.UNSUPPORTED) {
            return Mono.error(new UnsupportedBindingTypeException(registry.schemaUriOf(credentialConfigurationId)));
        }
        CatalogEntry entry = catalogEntryFiller.fill(new CatalogEntry(credentialConfigurationId, null, true,
                declaredModes, null, null, List.of(), 0, null, null));
        // Created by someone else since the read: start over and update it instead.
        return catalogEntryPort.insert(entry)
                .onErrorMap(CatalogEntryAlreadyExistsException.class, e -> new ConcurrentEntryChange())
                .then();
    }

    /** Writes only if nobody changed the entry since it was read, otherwise the whole replacement starts over. */
    private Mono<Void> write(CatalogEntry before, CatalogEntry after) {
        return catalogEntryPort.updateIfVersion(after, before.version())
                .flatMap(updated -> updated.isPresent()
                        ? Mono.<Void>empty()
                        : Mono.<Void>error(new ConcurrentEntryChange()));
    }

    private Set<DeliveryMode> storedOrCeilingModes(CatalogEntry stored) {
        return stored.deliveryModes() == null || stored.deliveryModes().isEmpty()
                ? schemaDeliveryCeiling.resolveEligibleModes(stored.credentialConfigurationId())
                : stored.deliveryModes();
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

    /** Another write changed an entry between this one's read and its update. */
    private static final class ConcurrentEntryChange extends RuntimeException {
        ConcurrentEntryChange() {
            super("A catalog entry was changed concurrently", null, false, false);
        }
    }

}
