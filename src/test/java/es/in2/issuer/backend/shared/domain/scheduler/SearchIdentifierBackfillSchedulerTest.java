package es.in2.issuer.backend.shared.domain.scheduler;

import es.in2.issuer.backend.shared.domain.service.SearchIdentifierIndexer;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SearchIdentifierBackfillSchedulerTest {

    @Mock private TenantRegistryService tenantRegistryService;
    @Mock private SearchIdentifierIndexer searchIdentifierIndexer;
    @InjectMocks private SearchIdentifierBackfillScheduler scheduler;

    @Test
    void backfill_goesThroughEveryActiveTenant() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("sandbox", "cgcom")));
        when(searchIdentifierIndexer.reindexTenants(List.of("sandbox", "cgcom"))).thenReturn(Mono.empty());

        StepVerifier.create(scheduler.backfill()).verifyComplete();

        verify(searchIdentifierIndexer).reindexTenants(List.of("sandbox", "cgcom"));
    }

    @Test
    void backfill_withoutTheTenantRegistry_isSkipped_andTriedAgainNextTime() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.error(new IllegalStateException("db down")));

        StepVerifier.create(scheduler.backfill()).verifyComplete();

        verify(searchIdentifierIndexer, never()).reindexTenants(any());
    }
}
