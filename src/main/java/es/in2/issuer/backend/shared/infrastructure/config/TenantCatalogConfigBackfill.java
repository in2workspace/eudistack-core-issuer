package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.service.CatalogEntryFiller;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Fills, for every active tenant, the catalog entries that predate V15 (EUD-266): schema URI,
 * delivery modes, validity and subject, copied from the credential type files by
 * {@link CatalogEntryFiller}. SQL cannot read those files, hence this runner after
 * {@link TenantSchemaFlywayMigrator}.
 *
 * <p>Idempotent: an entry that is already complete is not written. A failure in one tenant is logged
 * and does not stop the others nor the start-up; the entries it leaves unfilled are filled when read
 * (D13), as are the rows platform-dev seeds while the issuer is already serving requests.
 */
@Slf4j
@Component
@Order(2)
@RequiredArgsConstructor
public class TenantCatalogConfigBackfill implements ApplicationRunner {

    private final TenantRegistryService tenantRegistryService;
    private final CatalogEntryPort catalogEntryPort;
    private final CatalogEntryFiller catalogEntryFiller;

    @Override
    public void run(ApplicationArguments args) {
        Integer filled = backfillAllTenants().block();
        log.info("Catalog entry backfill completed: {} entries filled", filled);
    }

    /** @return how many entries were filled across all active tenants */
    public Mono<Integer> backfillAllTenants() {
        return tenantRegistryService.getActiveTenantSchemas()
                .onErrorResume(e -> {
                    log.warn("Could not load tenants from tenant_registry for the catalog backfill: {}", e.getMessage());
                    return Mono.just(List.of());
                })
                .flatMapMany(Flux::fromIterable)
                .concatMap(this::backfillTenantSafely)
                .reduce(0, Integer::sum);
    }

    private Mono<Integer> backfillTenantSafely(String tenant) {
        return backfillTenant(tenant)
                .onErrorResume(e -> {
                    log.error("Catalog entry backfill failed for tenant '{}': {}", tenant, e.getMessage());
                    return Mono.just(0);
                });
    }

    /** @return how many entries of the tenant were filled */
    public Mono<Integer> backfillTenant(String tenant) {
        return catalogEntryPort.findAll()
                .concatMap(this::fillIfNeeded)
                .reduce(0, Integer::sum)
                .doOnNext(filled -> log.info("Catalog backfill for tenant '{}': {} entries filled", tenant, filled))
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, tenant));
    }

    private Mono<Integer> fillIfNeeded(CatalogEntry entry) {
        CatalogEntry filled = catalogEntryFiller.fill(entry);
        if (filled.equals(entry)) {
            if (!entry.isFilled()) {
                log.warn("Catalog entry '{}' cannot be filled: no credential type file is loaded for it",
                        entry.credentialConfigurationId());
            }
            return Mono.just(0);
        }
        // Guarded by the version: if a PUT or a read-time fill got there first, theirs stands.
        return catalogEntryPort.updateIfVersion(filled, entry.version())
                .map(updated -> updated.isPresent() ? 1 : 0);
    }
}
