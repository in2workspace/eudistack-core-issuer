package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.model.entities.TenantRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantRegistryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TenantRegistryServiceImplTest {

    private TenantRegistryRepository repository;
    private TenantRegistryServiceImpl service;

    @BeforeEach
    void setUp() {
        repository = mock(TenantRegistryRepository.class);
        service = new TenantRegistryServiceImpl(repository);
    }

    private static TenantRegistry tenant(String schema, String displayName) {
        return new TenantRegistry(schema, displayName, "simple", "active", null, null);
    }

    @Test
    void getDisplayName_tenantWithDisplayName_returnsIt() {
        when(repository.findById("dome")).thenReturn(Mono.just(tenant("dome", "DOME Marketplace")));

        StepVerifier.create(service.getDisplayName("dome")).expectNext("DOME Marketplace").verifyComplete();
    }

    @Test
    void getDisplayName_blankDisplayName_fallsBackToSchemaName() {
        when(repository.findById("dome")).thenReturn(Mono.just(tenant("dome", " ")));

        StepVerifier.create(service.getDisplayName("dome")).expectNext("dome").verifyComplete();
    }

    @Test
    void getDisplayName_nullDisplayName_fallsBackToSchemaName() {
        when(repository.findById("dome")).thenReturn(Mono.just(tenant("dome", null)));

        StepVerifier.create(service.getDisplayName("dome")).expectNext("dome").verifyComplete();
    }

    @Test
    void getDisplayName_unknownTenant_fallsBackToSchemaName() {
        when(repository.findById("ghost")).thenReturn(Mono.empty());

        StepVerifier.create(service.getDisplayName("ghost")).expectNext("ghost").verifyComplete();
    }

    @Test
    void getDisplayName_secondCall_isServedFromCache() {
        when(repository.findById("dome")).thenReturn(Mono.just(tenant("dome", "DOME Marketplace")));

        service.getDisplayName("dome").block();
        StepVerifier.create(service.getDisplayName("dome")).expectNext("DOME Marketplace").verifyComplete();

        verify(repository, times(1)).findById("dome");
    }
}
