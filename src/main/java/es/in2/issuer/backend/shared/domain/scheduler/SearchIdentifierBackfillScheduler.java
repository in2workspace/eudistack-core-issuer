package es.in2.issuer.backend.shared.domain.scheduler;

import es.in2.issuer.backend.shared.domain.service.SearchIdentifierIndexer;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The background calculation of the search identifier fingerprints in every active tenant (EUD-267, FR-09 of
 * EUD-169): the initial load of the processes already issued, an identifier added to an entry, a rotated tenant key,
 * and anything a previous run could not finish. Only the entries that are not indexed with what they declare now are
 * done, so a run with nothing to do only reads the catalog. It may run on several instances at once: computing the
 * same fingerprints twice writes the same rows.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SearchIdentifierBackfillScheduler {

    private final TenantRegistryService tenantRegistryService;
    private final SearchIdentifierIndexer searchIdentifierIndexer;

    @Scheduled(cron = "${issuer.search-identifiers.backfill-cron:0 */5 * * * *}")
    public Mono<Void> backfill() {
        return tenantRegistryService.getActiveTenantSchemas()
                .flatMap(searchIdentifierIndexer::reindexTenants)
                .onErrorResume(e -> {
                    log.warn("Search identifier backfill skipped: {}", e.toString());
                    return Mono.empty();
                });
    }
}
