package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.PreconditionFailedException;
import es.in2.issuer.backend.shared.domain.exception.PreconditionRequiredException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryChange;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryETag;
import es.in2.issuer.backend.shared.domain.model.catalog.CreateCatalogEntryCommand;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.domain.spi.CredentialProfileCatalog;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.util.function.Supplier;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * The tenant's catalog of attestations, one entry per credential type with the configuration the
 * tenant gave it (EUD-266, Attestation Catalogue API).
 *
 * <p>Writes are guarded by optimistic concurrency (FR-05): the version of the entry is its strong ETag,
 * and a replace or an enable/disable carries it as {@code If-Match}. A missing {@code If-Match} (or
 * {@code *}, which would match any version and defeat the guard, D16) is
 * {@link PreconditionRequiredException}; one that does not match, weak ones included, is
 * {@link PreconditionFailedException}. Every write runs in a transaction and drops the
 * {@link TenantCredentialProfileService} cache of this instance once it has committed, so issuance and
 * the OID4VCI metadata stop seeing what was disabled. Once committed, each change is also audited, one
 * event per entry (AC-12, see {@link CatalogEntryChangeAuditor}). A write rejected for a business reason
 * (a {@link CatalogConfigurationException} with a business code) is audited as denied, too.
 *
 * <p>A row that predates the entry configuration (seeded while the issuer was running) is completed
 * from its credential type file when it is read, and stored (D13). Entries are returned ready to
 * present: the schema URI is the stored one or, while the type file declares none, the synthetic one.
 *
 * <p>Every operation needs a tenant in the Reactor context and fails with
 * {@link TenantNotResolvedException} without it, instead of falling back to a default schema.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AttestationCatalogService {

    private final CatalogEntryPort catalogEntryPort;
    private final CatalogEntryFiller catalogEntryFiller;
    private final CatalogEntryValidator catalogEntryValidator;
    private final CredentialProfileCatalog credentialProfileCatalog;
    private final TenantCredentialProfileService tenantCredentialProfileService;
    private final TransactionalOperator transactionalOperator;
    private final CatalogEntryChangeAuditor changeAuditor;

    /** The entries of the tenant, only the enabled or only the disabled ones when {@code enabled} is given. */
    public Flux<CatalogEntry> list(Boolean enabled) {
        return Flux.deferContextual(ctx -> {
            requireTenant(ctx);
            Flux<CatalogEntry> rows = enabled == null
                    ? catalogEntryPort.findAll()
                    : catalogEntryPort.findAllByEnabled(enabled);
            // Collected first: filling an entry writes, and must not compete with the open read for a connection.
            return rows.collectList()
                    .flatMapMany(Flux::fromIterable)
                    .concatMap(this::fillOnRead)
                    .map(this::withResolvedSchemaUri);
        });
    }

    /** @throws CatalogEntryNotFoundException if the tenant has no such entry */
    public Mono<CatalogEntry> get(String credentialConfigurationId) {
        return Mono.deferContextual(ctx -> {
            requireTenant(ctx);
            return findExisting(credentialConfigurationId)
                    .flatMap(this::fillOnRead)
                    .map(this::withResolvedSchemaUri);
        });
    }

    /**
     * @throws es.in2.issuer.backend.shared.domain.exception.CatalogConfigurationException if the
     *         configuration is not valid
     * @throws es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException if the
     *         schema already has an entry
     */
    public Mono<CatalogEntry> create(CreateCatalogEntryCommand command) {
        Mono<CatalogEntry> create = Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx);
            CatalogEntry entry = catalogEntryValidator.validateForCreate(command);
            return committed(tenant, catalogEntryPort.insert(entry).map(this::createdChange))
                    .doOnNext(created -> log.info("Catalog entry '{}' created for tenant '{}'",
                            created.credentialConfigurationId(), tenant))
                    .map(CatalogEntryChange::after)
                    .map(this::withResolvedSchemaUri);
        });
        // The entry of a create is known only if its schema resolves.
        return auditIfInvalid(create, CatalogEntryChange.Operation.CREATE,
                () -> credentialProfileCatalog.resolveSchemaUri(command.schemaUri()).orElse(null));
    }

    /**
     * Replaces the configuration of an entry; its schema does not change.
     *
     * @param ifMatch the {@code If-Match} header as received, {@code null} if absent
     */
    public Mono<CatalogEntry> replace(String credentialConfigurationId, CatalogConfigurationInput configuration,
                                      String ifMatch) {
        Mono<CatalogEntry> update = Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx);
            requireIfMatch(ifMatch);
            Mono<CatalogEntryChange> replace = findExisting(credentialConfigurationId)
                    .flatMap(current -> {
                        requireCurrentVersion(ifMatch, current);
                        CatalogEntry replacement =
                                catalogEntryValidator.validateForReplace(credentialConfigurationId, configuration);
                        if (change(CatalogEntryChange.Operation.UPDATE, current, replacement).isEmpty()) {
                            // The configuration it already has: nothing is written, so its version and ETag
                            // stay as they are and there is no change to audit.
                            return Mono.just(change(CatalogEntryChange.Operation.UPDATE, current, current));
                        }
                        return updateIfVersion(replacement, current.version())
                                .map(updated -> change(CatalogEntryChange.Operation.UPDATE, current, updated));
                    });
            return committed(tenant, replace)
                    .doOnNext(change -> log.info(change.isEmpty()
                                    ? "Catalog entry '{}' left unchanged for tenant '{}'"
                                    : "Catalog entry '{}' replaced for tenant '{}'",
                            change.credentialConfigurationId(), tenant))
                    .map(CatalogEntryChange::after)
                    .map(this::withResolvedSchemaUri);
        });
        return auditIfInvalid(update, CatalogEntryChange.Operation.UPDATE, () -> credentialConfigurationId);
    }

    /**
     * Enables or disables an entry. Enabling one without delivery modes is rejected.
     *
     * @param ifMatch the {@code If-Match} header as received, {@code null} if absent
     */
    public Mono<CatalogEntry> setEnabled(String credentialConfigurationId, boolean enabled, String ifMatch) {
        CatalogEntryChange.Operation operation =
                enabled ? CatalogEntryChange.Operation.ENABLE : CatalogEntryChange.Operation.DISABLE;
        Mono<CatalogEntry> toggle = Mono.deferContextual(ctx -> {
            String tenant = requireTenant(ctx);
            requireIfMatch(ifMatch);
            Mono<CatalogEntryChange> toggled = findExisting(credentialConfigurationId)
                    .flatMap(current -> toggle(current, enabled, operation, ifMatch));
            return committed(tenant, toggled)
                    .doOnNext(done -> logToggled(done, enabled, tenant))
                    .map(CatalogEntryChange::after)
                    .map(this::withResolvedSchemaUri);
        });
        return auditIfInvalid(toggle, operation, () -> credentialConfigurationId);
    }

    private Mono<CatalogEntryChange> toggle(CatalogEntry current, boolean enabled,
                                            CatalogEntryChange.Operation operation, String ifMatch) {
        requireCurrentVersion(ifMatch, current);
        // Filled in the same write: a row not configured yet leaves with its configuration (D13).
        CatalogEntry target = catalogEntryFiller.fill(current).withEnabled(enabled);
        if (!target.isFilled()) {
            // Its type file is not loaded, so it cannot be completed: it does not exist for the
            // API (see get), and writing it only to answer 404 would change it for nothing.
            return Mono.error(new CatalogEntryNotFoundException(current.credentialConfigurationId()));
        }
        if (enabled) {
            catalogEntryValidator.validateEnabling(target);
        }
        if (target.equals(current)) {
            // Already as asked, and nothing to fill in: nothing is written, so its version and
            // ETag stay as they are and there is no change to audit. A row that still needs
            // its configuration filled in (D13) is not equal to its target, and is written.
            return Mono.just(change(operation, current, current));
        }
        return updateIfVersion(target, current.version())
                .map(updated -> change(operation, current, updated));
    }

    private static void logToggled(CatalogEntryChange done, boolean enabled, String tenant) {
        if (done.isEmpty()) {
            log.info("Catalog entry '{}' left unchanged for tenant '{}'", done.credentialConfigurationId(), tenant);
        } else {
            log.info("Catalog entry '{}' {} for tenant '{}'",
                    done.credentialConfigurationId(), enabled ? "enabled" : "disabled", tenant);
        }
    }

    // ---- persistence -----------------------------------------------------------

    private Mono<CatalogEntry> findExisting(String credentialConfigurationId) {
        return catalogEntryPort.findById(credentialConfigurationId)
                .switchIfEmpty(Mono.error(() -> new CatalogEntryNotFoundException(credentialConfigurationId)));
    }

    /**
     * Writes only if the version is still {@code expectedVersion}. When nothing is written the entry was
     * either changed by someone else in between (412) or deleted (404): the re-read tells which.
     */
    private Mono<CatalogEntry> updateIfVersion(CatalogEntry entry, long expectedVersion) {
        return catalogEntryPort.updateIfVersion(entry, expectedVersion)
                .flatMap(updated -> updated.map(Mono::just).orElseGet(() ->
                        findExisting(entry.credentialConfigurationId())
                                .flatMap(current -> Mono.<CatalogEntry>error(staleVersion()))));
    }

    /**
     * D13: completes a row that has not been configured yet from its credential type file and stores
     * it. If someone else changed the row first, the current one is read again as it is.
     */
    private Mono<CatalogEntry> fillOnRead(CatalogEntry entry) {
        CatalogEntry filled = catalogEntryFiller.fill(entry);
        if (filled.equals(entry)) {
            return Mono.just(entry);
        }
        return catalogEntryPort.updateIfVersion(filled, entry.version())
                .flatMap(updated -> updated.map(Mono::just)
                        .orElseGet(() -> catalogEntryPort.findById(entry.credentialConfigurationId())))
                .doOnNext(stored -> log.info("Catalog entry '{}' completed from its credential type file",
                        stored.credentialConfigurationId()));
    }

    /**
     * Runs {@code operation} in a transaction and, once it has committed, drops this instance's cache and
     * audits the change. An empty change wrote nothing, so neither is needed. Emits the change.
     */
    private Mono<CatalogEntryChange> committed(String tenant, Mono<CatalogEntryChange> operation) {
        return transactionalOperator.transactional(operation)
                .flatMap(change -> {
                    if (change.isEmpty()) {
                        return Mono.just(change);
                    }
                    tenantCredentialProfileService.invalidateCache(tenant);
                    return changeAuditor.audit(change).thenReturn(change);
                });
    }

    /**
     * Passes {@code write} through, and when it is rejected for a business reason (a
     * {@link CatalogConfigurationException} with a code other than {@code BAD_REQUEST}:
     * {@code unknown_schema}, {@code unsupported_binding_type}, {@code field_not_in_schema},
     * {@code invalid_validity}, {@code no_delivery_mode}) records a denied {@code InvalidConfiguration} event. A body of the wrong shape is not audited, and neither are the
     * 404, 409, 412 and 428, which are not the catalog refusing a configuration.
     *
     * @param credentialConfigurationId the entry the write is about, {@code null} when it is not known
     */
    private <T> Mono<T> auditIfInvalid(Mono<T> write, CatalogEntryChange.Operation operation,
                                       Supplier<String> credentialConfigurationId) {
        return write.onErrorResume(CatalogConfigurationException.class, e -> {
            if (CatalogConfigurationException.BAD_REQUEST.equals(e.code())) {
                return Mono.error(e);
            }
            return changeAuditor.auditDenied(operation, credentialConfigurationId.get(),
                            CatalogEntryChangeAuditor.INVALID_CONFIGURATION)
                    .then(Mono.error(e));
        });
    }

    // ---- preconditions ---------------------------------------------------------

    private static void requireIfMatch(String ifMatch) {
        if (ifMatch == null || ifMatch.isBlank()) {
            throw new PreconditionRequiredException("The If-Match header is required: send the ETag of the entry");
        }
        if ("*".equals(ifMatch.strip())) {
            throw new PreconditionRequiredException(
                    "If-Match: * is not supported, it would overwrite any version: send the ETag of the entry");
        }
    }

    private static void requireCurrentVersion(String ifMatch, CatalogEntry current) {
        if (!CatalogEntryETag.matches(ifMatch, current.version())) {
            throw staleVersion();
        }
    }

    private static PreconditionFailedException staleVersion() {
        return new PreconditionFailedException(
                "If-Match does not match the current version of the entry: it was changed by someone else, read it again");
    }

    // ---- helpers ---------------------------------------------------------------

    private CatalogEntryChange createdChange(CatalogEntry created) {
        return CatalogEntryChange.created(withResolvedSchemaUri(created));
    }

    private CatalogEntryChange change(CatalogEntryChange.Operation operation, CatalogEntry before, CatalogEntry after) {
        return new CatalogEntryChange(operation, withResolvedSchemaUri(before), withResolvedSchemaUri(after));
    }

    /** A stored entry shows the synthetic schema URI while its type file still declares no real one. */
    private CatalogEntry withResolvedSchemaUri(CatalogEntry entry) {
        return entry.schemaUri() != null
                ? entry
                : entry.withSchemaUri(credentialProfileCatalog.schemaUriOf(entry.credentialConfigurationId()));
    }

    /** Admin paths never fall back to a default schema when the tenant is missing. */
    private static String requireTenant(ContextView ctx) {
        String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
        if (tenant.isBlank()) {
            throw new TenantNotResolvedException("Tenant context not resolved");
        }
        return tenant;
    }
}
