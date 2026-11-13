package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprint;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprinter;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierIndexState;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.shared.domain.spi.SearchIdentifierStore;
import es.in2.issuer.backend.shared.domain.spi.SearchIdentifierStore.StoredAttestation;
import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Fingerprints of the search identifiers of the issuance processes (EUD-267: FR-11 and AC-14 of EUD-254, FR-09 and
 * AC-10 of EUD-169), computed with the single {@link SearchIdentifierFingerprinter}.
 *
 * <ul>
 *   <li><b>On issuance</b> ({@link #saveWithFingerprints}): the process and one fingerprint per identifier that its
 *       catalog entry declares and its attestation contains are written in one transaction, so there is no process
 *       without its fingerprints. The entry is read with a shared lock in that transaction, so a change of its
 *       identifiers waits for this issuance and then sees it. When the entry declares identifiers and the tenant
 *       key cannot be read, nothing is written.</li>
 *   <li><b>In the background</b> ({@link #reindexTenant}): the processes already issued are fingerprinted again
 *       from the attestation data each one stores, for every entry that has not been indexed yet (the initial load),
 *       whose identifiers changed (one added, changed or removed), or whose tenant key was rotated. It runs once a
 *       catalog change commits ({@link #reindexInBackground}) and periodically, which also retries what failed.</li>
 * </ul>
 * Neither a value nor a fingerprint is logged, returned or traced.
 */
@Slf4j
@Service
public class SearchIdentifierIndexer {

    /** Processes read per page by the background calculation, so no read stays open while it writes. */
    static final int PAGE_SIZE = 200;

    private final CatalogEntryPort catalogEntryPort;
    private final IssuancePort issuancePort;
    private final SearchIdentifierStore store;
    private final TenantSecretKeyPort tenantSecretKeyPort;
    private final TransactionalOperator transactionalOperator;
    private final ObjectMapper objectMapper;
    /** Tenants whose background calculation runs in this instance, and whether it must run again when it ends. */
    private final Map<String, Boolean> running = new ConcurrentHashMap<>();

    public SearchIdentifierIndexer(CatalogEntryPort catalogEntryPort, IssuancePort issuancePort,
                                   SearchIdentifierStore store, TenantSecretKeyPort tenantSecretKeyPort,
                                   TransactionalOperator transactionalOperator, ObjectMapper objectMapper) {
        this.catalogEntryPort = catalogEntryPort;
        this.issuancePort = issuancePort;
        this.store = store;
        this.tenantSecretKeyPort = tenantSecretKeyPort;
        this.transactionalOperator = transactionalOperator;
        this.objectMapper = objectMapper;
    }

    // ---- on issuance ------------------------------------------------------------------------------------------

    /**
     * Inserts a new issuance process with the fingerprints of its search identifiers, in one transaction. The
     * process's {@code credentialType} names its catalog entry, and its {@code credentialDataSet} is the attestation
     * as built, from which the identifiers are read.
     *
     * @throws es.in2.issuer.backend.shared.domain.exception.TenantSecretKeyUnavailableException (as the error) when
     *         the entry declares identifiers and the tenant key cannot be read: nothing is written
     */
    public Mono<Issuance> saveWithFingerprints(Issuance issuance) {
        return Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, ""));
            Mono<Issuance> write = catalogEntryPort.findByIdForShare(issuance.getCredentialType())
                    .map(CatalogEntry::searchIdentifiers)
                    .defaultIfEmpty(List.of())
                    .flatMap(identifiers -> identifiers.isEmpty()
                            ? issuancePort.insert(issuance)
                            : tenantSecretKeyPort.keyOf(tenant)
                                    .map(key -> fingerprintsOf(key, identifiers, issuance.getCredentialDataSet()))
                                    .flatMap(fingerprints -> issuancePort.insert(issuance)
                                            .flatMap(saved -> store.insertAll(saved.getIssuanceId(), fingerprints)
                                                    .thenReturn(saved))));
            return transactionalOperator.transactional(write)
                    .doOnSuccess(saved -> log.info("Created issuance: {}", saved.getIssuanceId()));
        });
    }

    // ---- in the background ------------------------------------------------------------------------------------

    /**
     * Starts {@link #reindexTenant} for the tenant without waiting for it. If it is already running in this
     * instance, it runs once more when it ends, so a change made meanwhile is not missed.
     */
    public void reindexInBackground(String tenant) {
        AtomicBoolean start = new AtomicBoolean();
        running.compute(tenant, (name, again) -> {
            if (again == null) {
                start.set(true);
                return Boolean.FALSE;
            }
            return Boolean.TRUE;
        });
        if (start.get()) {
            runGuarded(tenant).subscribeOn(Schedulers.boundedElastic()).subscribe();
        }
    }

    /**
     * {@link #reindexTenant} for every tenant, one after the other, skipping a tenant whose calculation is already
     * running in this instance. A failing tenant is logged and does not stop the others.
     */
    public Mono<Void> reindexTenants(List<String> tenants) {
        return Flux.fromIterable(tenants)
                .concatMap(tenant -> running.putIfAbsent(tenant, Boolean.FALSE) == null
                        ? runGuarded(tenant)
                        : Mono.empty())
                .then();
    }

    private Mono<Void> runGuarded(String tenant) {
        return reindexTenant()
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .onErrorResume(e -> {
                    log.warn("Search identifiers of tenant '{}' not indexed: {}", tenant, e.toString());
                    return Mono.empty();
                })
                .then(Mono.defer(() -> {
                    AtomicBoolean again = new AtomicBoolean();
                    running.computeIfPresent(tenant, (name, requested) -> {
                        again.set(requested);
                        return null;
                    });
                    return again.get() ? Mono.fromRunnable(() -> reindexInBackground(tenant)) : Mono.<Void>empty();
                }));
    }

    /**
     * Fingerprints again the processes of every catalog entry of the tenant (in the Reactor context) that is not
     * indexed with the identifiers it declares and the current tenant key. Entries are done one after the other.
     */
    public Mono<Void> reindexTenant() {
        return Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, ""));
            // Read first, so no read stays open while the entries are written.
            Mono<Map<String, SearchIdentifierIndexState>> states = store.findAllStates()
                    .collectMap(SearchIdentifierIndexState::credentialConfigurationId, Function.identity());
            Mono<List<CatalogEntry>> entries = catalogEntryPort.findAll().collectList();
            // The key is read only if an entry declares identifiers, and once per run.
            Mono<byte[]> key = Mono.defer(() -> tenantSecretKeyPort.keyOf(tenant)).cache();
            return Mono.zip(entries, states)
                    .flatMapMany(both -> Flux.fromIterable(both.getT1())
                            .concatMap(entry -> reindexIfStale(entry, both.getT2().get(entry.credentialConfigurationId()),
                                    key)))
                    .then();
        });
    }

    private Mono<Void> reindexIfStale(CatalogEntry entry, SearchIdentifierIndexState state, Mono<byte[]> key) {
        String id = entry.credentialConfigurationId();
        String signature = signatureOf(entry.searchIdentifiers());
        if (entry.searchIdentifiers().isEmpty()) {
            if (state != null && signature.equals(state.searchIdentifiers())) {
                return Mono.empty();
            }
            // Its identifiers were removed (or never indexed): its processes cannot be searched by any.
            return store.deleteAllOfType(id)
                    .then(store.saveState(new SearchIdentifierIndexState(id, signature, null)))
                    .doOnSuccess(done -> log.info("Search identifiers of entry '{}' removed from its processes", id));
        }
        return key.flatMap(tenantKey -> {
            String keyId = SearchIdentifierFingerprinter.keyId(tenantKey);
            if (state != null && signature.equals(state.searchIdentifiers()) && keyId.equals(state.keyId())) {
                return Mono.empty();
            }
            return reindexEntry(entry, tenantKey)
                    .flatMap(count -> store.saveState(new SearchIdentifierIndexState(id, signature, keyId))
                            .doOnSuccess(done -> log.info(
                                    "Search identifiers of entry '{}' computed for {} issued process(es)", id, count)));
        });
    }

    /** Fingerprints again every process of the entry, page by page; emits how many processes it went through. */
    private Mono<Long> reindexEntry(CatalogEntry entry, byte[] tenantKey) {
        return page(entry, tenantKey, null, 0L);
    }

    private Mono<Long> page(CatalogEntry entry, byte[] tenantKey, UUID after, long done) {
        return store.processesOfType(entry.credentialConfigurationId(), after, PAGE_SIZE).collectList()
                .flatMap(processes -> {
                    if (processes.isEmpty()) {
                        return Mono.just(done);
                    }
                    UUID last = processes.getLast().issuanceId();
                    return Flux.fromIterable(processes)
                            .concatMap(process -> reindexProcess(entry, tenantKey, process))
                            .then(Mono.defer(() -> processes.size() < PAGE_SIZE
                                    ? Mono.just(done + processes.size())
                                    : page(entry, tenantKey, last, done + processes.size())));
                });
    }

    private Mono<Void> reindexProcess(CatalogEntry entry, byte[] tenantKey, StoredAttestation process) {
        List<SearchIdentifierFingerprint> fingerprints;
        try {
            fingerprints = fingerprintsOf(tenantKey, entry.searchIdentifiers(), process.credentialDataSet());
        } catch (IllegalStateException e) {
            // A process whose stored data is not an attestation cannot be searched; the others go on.
            log.warn("Search identifiers of process {} not computed: its attestation data cannot be read",
                    process.issuanceId());
            return Mono.empty();
        }
        return transactionalOperator.transactional(store.replaceAll(process.issuanceId(), fingerprints));
    }

    // ---- shared -----------------------------------------------------------------------------------------------

    private List<SearchIdentifierFingerprint> fingerprintsOf(byte[] tenantKey,
                                                              List<CatalogEntry.SearchIdentifier> identifiers,
                                                              String credentialDataSet) {
        if (credentialDataSet == null || credentialDataSet.isBlank()) {
            return List.of();
        }
        JsonNode attestation;
        try {
            attestation = objectMapper.readTree(credentialDataSet);
        } catch (JsonProcessingException e) {
            // The message of the parser would quote the data: it is not kept.
            throw new IllegalStateException("The attestation data of the process is not JSON");
        }
        return SearchIdentifierFingerprinter.fingerprintsOf(tenantKey, identifiers, attestation);
    }

    /**
     * A canonical signature of the identifiers of an entry: name and path of each, in order. Two entries index the
     * same way exactly when their signatures are equal.
     */
    public static String signatureOf(List<CatalogEntry.SearchIdentifier> identifiers) {
        StringBuilder signature = new StringBuilder("[");
        for (CatalogEntry.SearchIdentifier identifier : identifiers) {
            if (signature.length() > 1) {
                signature.append(',');
            }
            signature.append('{').append(quoted(identifier.name())).append(':').append('[');
            List<String> segments = identifier.field().segments();
            for (int i = 0; i < segments.size(); i++) {
                if (i > 0) {
                    signature.append(',');
                }
                signature.append(quoted(segments.get(i)));
            }
            signature.append("]}");
        }
        return signature.append(']').toString();
    }

    private static String quoted(String value) {
        return '"' + value.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
    }

    private static String requireTenant(String tenant) {
        if (tenant == null || tenant.isBlank()) {
            throw new TenantNotResolvedException("Tenant context not resolved");
        }
        return tenant;
    }
}
