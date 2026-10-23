package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.service.CatalogEntryFiller;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TenantCatalogConfigBackfillTest {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    @Mock private TenantRegistryService tenantRegistryService;
    @Mock private CatalogEntryPort catalogEntryPort;

    private CatalogEntryFiller filler;
    private TenantCatalogConfigBackfill backfill;

    @BeforeEach
    void setUp() {
        CredentialProfileRegistry registry = new CredentialProfileRegistry(
                OBJECT_MAPPER, new PathMatchingResourcePatternResolver(), "classpath:catalog-profiles");
        filler = new CatalogEntryFiller(registry, new SchemaDeliveryCeiling(registry));
        backfill = new TenantCatalogConfigBackfill(tenantRegistryService, catalogEntryPort, filler);
    }

    @Test
    void backfillTenant_writesTheFilledEntryGuardedByTheStoredVersion() {
        CatalogEntry seeded = unfilled("doctorid.sd.1", 7);
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(seeded));
        when(catalogEntryPort.updateIfVersion(any(), anyLong())).thenReturn(Mono.just(Optional.of(seeded)));

        Integer filled = backfill.backfillTenant("e2e-tenant-a").block();

        assertThat(filled).isEqualTo(1);
        ArgumentCaptor<CatalogEntry> written = ArgumentCaptor.forClass(CatalogEntry.class);
        verify(catalogEntryPort).updateIfVersion(written.capture(), eq(7L));
        assertThat(written.getValue().validity()).isNotNull();
        assertThat(written.getValue().deliveryModes()).isNotEmpty();
    }

    @Test
    void backfillTenant_doesNotWriteAnEntryThatIsAlreadyFilled() {
        CatalogEntry filled = filler.fill(unfilled("doctorid.sd.1", 0));
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(filled));

        Integer count = backfill.backfillTenant("e2e-tenant-a").block();

        assertThat(count).isZero();
        verify(catalogEntryPort, never()).updateIfVersion(any(), anyLong());
    }

    @Test
    void backfillTenant_doesNotWriteAnEntryWhoseTypeFileIsNotLoaded() {
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(unfilled("removed.type.1", 0)));

        Integer count = backfill.backfillTenant("e2e-tenant-a").block();

        assertThat(count).isZero();
        verify(catalogEntryPort, never()).updateIfVersion(any(), anyLong());
    }

    @Test
    void backfillTenant_doesNotCountAnEntryThatChangedConcurrently() {
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(unfilled("doctorid.sd.1", 0)));
        when(catalogEntryPort.updateIfVersion(any(), anyLong())).thenReturn(Mono.just(Optional.empty()));

        assertThat(backfill.backfillTenant("e2e-tenant-a").block()).isZero();
    }

    @Test
    void backfillAllTenants_readsEachTenantUnderItsOwnReactorContext() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("tenant-a", "tenant-b")));
        List<String> tenantsSeen = new ArrayList<>();
        when(catalogEntryPort.findAll()).thenReturn(Flux.deferContextual(ctx -> {
            tenantsSeen.add(ctx.get(TENANT_DOMAIN_CONTEXT_KEY));
            return Flux.empty();
        }));

        backfill.backfillAllTenants().block();

        assertThat(tenantsSeen).containsExactly("tenant-a", "tenant-b");
    }

    @Test
    void backfillAllTenants_addsUpTheEntriesFilledInEveryTenant() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("tenant-a", "tenant-b")));
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(unfilled("doctorid.sd.1", 0)));
        when(catalogEntryPort.updateIfVersion(any(), anyLong())).thenReturn(Mono.just(Optional.of(unfilled("x", 1))));

        assertThat(backfill.backfillAllTenants().block()).isEqualTo(2);
    }

    @Test
    void backfillAllTenants_aFailingTenantDoesNotStopTheOthers() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("broken", "healthy")));
        when(catalogEntryPort.findAll()).thenReturn(Flux.deferContextual(ctx ->
                "broken".equals(ctx.get(TENANT_DOMAIN_CONTEXT_KEY))
                        ? Flux.error(new IllegalStateException("schema missing"))
                        : Flux.just(unfilled("doctorid.sd.1", 0))));
        when(catalogEntryPort.updateIfVersion(any(), anyLong())).thenReturn(Mono.just(Optional.of(unfilled("x", 1))));

        assertThat(backfill.backfillAllTenants().block()).isEqualTo(1);
    }

    @Test
    void backfillAllTenants_whenTheRegistryCannotBeRead_fillsNothingAndDoesNotFail() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.error(new IllegalStateException("no registry")));

        assertThat(backfill.backfillAllTenants().block()).isZero();
    }

    private static CatalogEntry unfilled(String ccid, long version) {
        return new CatalogEntry(ccid, null, true, null, null, null, List.of(), version, null, null);
    }
}
