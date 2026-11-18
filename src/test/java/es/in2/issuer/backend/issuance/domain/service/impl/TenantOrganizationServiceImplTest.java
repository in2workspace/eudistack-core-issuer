package es.in2.issuer.backend.issuance.domain.service.impl;

import es.in2.issuer.backend.issuance.domain.exception.UnknownOrganizationException;
import es.in2.issuer.backend.shared.domain.exception.TenantConfigMissingException;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class TenantOrganizationServiceImplTest {

    private static final String TENANT = "cgcom";
    private static final String OWN_ORGANIZATION = "VATES-Q2866017C";
    private static final String OTHER_ORGANIZATION = "VATES-Z00000000";

    private TenantRegistryService tenantRegistryService;
    private TenantConfigService tenantConfigService;
    private TenantOrganizationServiceImpl service;

    @BeforeEach
    void setUp() {
        tenantRegistryService = mock(TenantRegistryService.class);
        tenantConfigService = mock(TenantConfigService.class);
        service = new TenantOrganizationServiceImpl(tenantRegistryService, tenantConfigService);
    }

    private Mono<Void> check(String organization) {
        return service.requireOrganizationOfTenant(organization)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private void ownOrganizationIs(String organization) {
        when(tenantConfigService.getStringOrThrow(TenantOrganizationServiceImpl.TENANT_ORGANIZATION_KEY))
                .thenReturn(Mono.just(organization));
    }

    @Test
    void aSimpleTenantAcceptsItsOwnOrganization() {
        when(tenantRegistryService.getTenantType(TENANT)).thenReturn(Mono.just("simple"));
        ownOrganizationIs(OWN_ORGANIZATION);

        StepVerifier.create(check(OWN_ORGANIZATION)).verifyComplete();
    }

    /** The case of the review: cgcom is simple, so VATES-Z00000000 is not one of its organizations. */
    @Test
    void aSimpleTenantRejectsAnyOtherOrganization() {
        when(tenantRegistryService.getTenantType(TENANT)).thenReturn(Mono.just("simple"));
        ownOrganizationIs(OWN_ORGANIZATION);

        StepVerifier.create(check(OTHER_ORGANIZATION))
                .expectError(UnknownOrganizationException.class)
                .verify();
    }

    /** TDG-25: a multi-organization tenant has no record of its organizations yet, so it accepts as before. */
    @Test
    void aMultiOrganizationTenantAcceptsAnyOrganization() {
        when(tenantRegistryService.getTenantType(TENANT)).thenReturn(Mono.just("multi_org"));

        StepVerifier.create(check(OTHER_ORGANIZATION)).verifyComplete();
        verifyNoInteractions(tenantConfigService);
    }

    /** Fail closed: a tenant without a registry row, or of any other type, is held to its own organization. */
    @ParameterizedTest
    @ValueSource(strings = {"platform", "unexpected"})
    void aTenantOfAnotherTypeIsHeldToItsOwnOrganization(String type) {
        when(tenantRegistryService.getTenantType(TENANT)).thenReturn(Mono.just(type));
        ownOrganizationIs(OWN_ORGANIZATION);

        StepVerifier.create(check(OTHER_ORGANIZATION))
                .expectError(UnknownOrganizationException.class)
                .verify();
    }

    @Test
    void aTenantWithoutARegistryRowIsHeldToItsOwnOrganization() {
        when(tenantRegistryService.getTenantType(TENANT)).thenReturn(Mono.empty());
        ownOrganizationIs(OWN_ORGANIZATION);

        StepVerifier.create(check(OTHER_ORGANIZATION))
                .expectError(UnknownOrganizationException.class)
                .verify();
    }

    /** Fail closed: without its own organization configured, a simple tenant cannot accept another one. */
    @Test
    void aSimpleTenantWithoutItsOrganizationConfiguredFails() {
        when(tenantRegistryService.getTenantType(TENANT)).thenReturn(Mono.just("simple"));
        when(tenantConfigService.getStringOrThrow(TenantOrganizationServiceImpl.TENANT_ORGANIZATION_KEY))
                .thenReturn(Mono.error(new TenantConfigMissingException(TENANT,
                        TenantOrganizationServiceImpl.TENANT_ORGANIZATION_KEY)));

        StepVerifier.create(check(OTHER_ORGANIZATION))
                .expectError(TenantConfigMissingException.class)
                .verify();
    }
}
