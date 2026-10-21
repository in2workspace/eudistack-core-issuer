package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.exception.CredentialConfigurationNotEnabledException;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.shared.domain.exception.InvalidDeliveryConfigException;
import es.in2.issuer.backend.shared.domain.exception.UnknownCredentialConfigurationException;
import es.in2.issuer.backend.shared.domain.exception.UnsupportedBindingTypeException;
import es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryChange;
import es.in2.issuer.backend.shared.domain.model.enums.BindingType;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.CatalogEntryChangeAuditor;
import es.in2.issuer.backend.shared.domain.service.CatalogEntryFiller;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.reactive.TransactionalOperator;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TenantCredentialProfileServiceImplTest {

    private static final String TENANT = "demo";

    @Mock private CatalogEntryPort catalogEntryPort;
    @Mock private CredentialProfileRegistry registry;
    @Mock private SchemaDeliveryCeiling schemaDeliveryCeiling;
    @Mock private TransactionalOperator transactionalOperator;
    @Mock private CatalogEntryChangeAuditor changeAuditor;

    private TenantCredentialProfileServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new TenantCredentialProfileServiceImpl(catalogEntryPort,
                new CatalogEntryFiller(registry, schemaDeliveryCeiling), registry, schemaDeliveryCeiling,
                transactionalOperator, changeAuditor);
        when(changeAuditor.auditAll(any())).thenReturn(Mono.empty());
        // Pass-through transaction: return the wrapped Mono unchanged.
        when(transactionalOperator.transactional(any(Mono.class)))
                .thenAnswer(inv -> inv.getArgument(0));
        // Default ceiling: everything eligible (unbound type). Tests that care about a
        // narrower ceiling override this for their specific credential_configuration_id.
        when(schemaDeliveryCeiling.resolveEligibleModes(anyString())).thenReturn(EnumSet.allOf(DeliveryMode.class));
        // Every type the tests mention has a file (the filler completes entries from it); no row exists
        // unless a test says so.
        when(registry.getByConfigurationId(anyString()))
                .thenAnswer(inv -> profile(inv.getArgument(0), null));
        when(registry.bindingTypeOf(anyString())).thenReturn(BindingType.KEY);
        when(catalogEntryPort.findAll()).thenReturn(Flux.empty());
        when(catalogEntryPort.insert(any())).thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(catalogEntryPort.updateIfVersion(any(), anyLong()))
                .thenAnswer(inv -> Mono.just(Optional.of(inv.getArgument(0))));
    }

    // ---- getCatalog -----------------------------------------------------------

    @Test
    void getCatalog_emptyTable_notConfigured() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "Profile A"),
                "B", profile("B", null)));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.empty());

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(CredentialCatalogNotConfiguredException.class)
                .verify();
    }

    /**
     * Stored ids that no longer exist in the registry leave every entry disabled, which is
     * indistinguishable from "never configured" for the admin UI → same 404.
     */
    @Test
    void getCatalog_storedIdsUnknownToRegistry_notConfigured() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("RETIRED")));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(CredentialCatalogNotConfiguredException.class)
                .verify();
    }

    @Test
    void getCatalog_withEnabledSubset_flagsPerTenant() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "A"),
                "B", profile("B", "B"),
                "C", profile("C", "C")));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A"), row("C")));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> {
                    assertThat(entry(list, "A").enabled()).isTrue();
                    assertThat(entry(list, "B").enabled()).isFalse();
                    assertThat(entry(list, "C").enabled()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void getCatalog_displayName_fallsBackToConfigurationId() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "Profile A"),
                "B", profile("B", null)));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A"), row("B")));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> {
                    assertThat(entry(list, "A").displayName()).isEqualTo("Profile A");
                    assertThat(entry(list, "B").displayName()).isEqualTo("B");
                })
                .verifyComplete();
    }

    /**
     * AC-01: each entry carries both the eligible modes (stored ∩ ceiling) and the schema
     * ceiling on its own, both in canonical (alphabetical) order.
     */
    @Test
    void getCatalog_enrichesWithDeliveryModesAndSchemaCeiling() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A", "email")));
        when(schemaDeliveryCeiling.resolveEligibleModes("A"))
                .thenReturn(EnumSet.allOf(DeliveryMode.class));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> {
                    CredentialCatalogEntryDto a = entry(list, "A");
                    assertThat(a.deliveryModes()).containsExactly("email");
                    assertThat(a.schemaEligibleModes()).containsExactly("direct", "email", "ui");
                })
                .verifyComplete();
    }

    /**
     * EC-05: a type disabled for the tenant still reports its schema ceiling, so the admin
     * UI can paint the full row.
     */
    @Test
    void getCatalog_disabledEntry_stillReportsSchemaCeiling() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "A"),
                "B", profile("B", "B")));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A")));
        when(schemaDeliveryCeiling.resolveEligibleModes("B"))
                .thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> {
                    CredentialCatalogEntryDto b = entry(list, "B");
                    assertThat(b.enabled()).isFalse();
                    assertThat(b.schemaEligibleModes()).containsExactly("email", "ui");
                })
                .verifyComplete();
    }

    /**
     * AC-03: a type with no explicit configuration is open to the entire schema ceiling.
     */
    @Test
    void getCatalog_noExplicitConfig_offersEntireCeiling() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A", null)));
        when(schemaDeliveryCeiling.resolveEligibleModes("A"))
                .thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> assertThat(entry(list, "A").deliveryModes()).containsExactly("email", "ui"))
                .verifyComplete();
    }

    /**
     * EC-04: a type whose stored configuration happens to equal the ceiling is
     * observably identical to one with no configuration at all (AC-03) -- and stays
     * that way even if the ceiling narrows later, unlike the unconfigured case.
     */
    @Test
    void getCatalog_configuredModesEqualCeiling_indistinguishableFromUnconfigured() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A", "email,ui")));
        when(schemaDeliveryCeiling.resolveEligibleModes("A"))
                .thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

        StepVerifier.create(service.getCatalog()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(list -> assertThat(entry(list, "A").deliveryModes()).containsExactly("email", "ui"))
                .verifyComplete();
    }

    // ---- read side: no rows ⇒ nothing enabled ---------------------------------

    @Test
    void isProfileAllowed_emptyTable_isFalse() {
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.empty());

        StepVerifier.create(service.isProfileAllowed("A")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    void getAvailableProfiles_emptyTable_isEmpty() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.empty());

        StepVerifier.create(service.getAvailableProfiles()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(profiles -> assertThat(profiles).isEmpty())
                .verifyComplete();
    }

    @Test
    void getAvailableProfiles_withEnabledSubset_returnsOnlyEnabled() {
        when(registry.getAllProfiles()).thenReturn(Map.of(
                "A", profile("A", "A"),
                "B", profile("B", "B")));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("B")));

        StepVerifier.create(service.getAvailableProfiles()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(profiles -> assertThat(profiles).containsOnlyKeys("B"))
                .verifyComplete();
    }

    @Test
    void getCatalog_noTenantInContext_badRequest() {
        StepVerifier.create(service.getCatalog())
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .verify();
    }

    @Test
    void findConfiguredDeliveryModes_notConfigured_returnsEmptySet() {
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A", null)));

        StepVerifier.create(service.findConfiguredDeliveryModes("A")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(modes -> assertThat(modes).isEmpty())
                .verifyComplete();
    }

    @Test
    void findConfiguredDeliveryModes_configured_returnsStoredModes() {
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A", "direct,email")));

        StepVerifier.create(service.findConfiguredDeliveryModes("A")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(modes -> assertThat(modes).containsExactlyInAnyOrder(DeliveryMode.DIRECT, DeliveryMode.EMAIL))
                .verifyComplete();
    }

    /**
     * Security review (F6): a type that is not enabled at all (absent from
     * findAllByEnabled(true)) must not be collapsed into the same empty Set as "enabled but
     * unconfigured" (see the passing test above) -- DeliveryEligibilityResolver would default
     * that to the schema ceiling, letting an unenabled type inherit eligibility instead of
     * being refused.
     */
    @Test
    void findConfiguredDeliveryModes_notEnabledAtAll_errorsWithNotEnabled() {
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A", "direct,email")));

        StepVerifier.create(service.findConfiguredDeliveryModes("unknown-or-not-enabled")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(CredentialConfigurationNotEnabledException.class)
                .verify();
    }

    /**
     * Security review (EUD-169): unlike getEnabledConfigurationIds() (tolerant, read by public
     * metadata), this feeds an issuance-time security decision and must fail closed rather than
     * silently resolve against the "unknown"/public schema.
     */
    @Test
    void findConfiguredDeliveryModes_noTenantInContext_badRequest() {
        StepVerifier.create(service.findConfiguredDeliveryModes("A"))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .verify();

        verify(catalogEntryPort, never()).findAllByEnabled(true);
    }

    /**
     * AC-06: the per-tenant cache keys on the tenant, so two tenants never see each
     * other's enabled ids even though the repository mock is shared.
     */
    @Test
    void twoTenants_haveIndependentEnabledIds() {
        when(catalogEntryPort.findAllByEnabled(true))
                .thenReturn(Flux.just(row("A")))
                .thenReturn(Flux.just(row("B")));

        StepVerifier.create(service.getEnabledConfigurationIds()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "tenant-1")))
                .assertNext(ids -> assertThat(ids).containsExactly("A"))
                .verifyComplete();
        StepVerifier.create(service.getEnabledConfigurationIds()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "tenant-2")))
                .assertNext(ids -> assertThat(ids).containsExactly("B"))
                .verifyComplete();

        verify(catalogEntryPort, times(2)).findAllByEnabled(true);
    }

    // ---- catalog entries of the cache -----------------------------------------

    @Test
    void findEnabledEntry_enabled_returnsTheEntryWithItsConfiguration() {
        CatalogEntry stored = new CatalogEntry("A", null, true, Set.of(DeliveryMode.EMAIL),
                new CatalogEntry.Validity(36500, false, null), null, List.of(), 4, Instant.now(), Instant.now());
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(stored));

        StepVerifier.create(service.findEnabledEntry("A")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectNext(stored)
                .verifyComplete();
    }

    @Test
    void findEnabledEntry_notEnabled_isEmpty() {
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A")));

        StepVerifier.create(service.findEnabledEntry("DISABLED")
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();
    }

    @Test
    void getEnabledConfigurationIds_loadsOnlyTheEnabledEntries() {
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A")));

        service.getEnabledConfigurationIds().contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();

        verify(catalogEntryPort, never()).findAll();
    }

    @Test
    void invalidateCache_makesTheNextReadReloadThatTenant() {
        when(catalogEntryPort.findAllByEnabled(true))
                .thenReturn(Flux.just(row("A")))
                .thenReturn(Flux.just(row("B")));

        service.getEnabledConfigurationIds().contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
        service.invalidateCache(TENANT);

        StepVerifier.create(service.getEnabledConfigurationIds()
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(ids -> assertThat(ids).containsExactly("B"))
                .verifyComplete();
    }

    // ---- updateCatalog (the deprecated alias: disables instead of deleting, EUD-266 D5) ----------

    @Test
    void updateCatalog_unknownId_failsFastWithoutWriting() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));

        StepVerifier.create(service.updateCatalog(Set.of("UNKNOWN"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(UnknownCredentialConfigurationException.class)
                .verify();

        verifyNothingWritten();
    }

    @Test
    void updateCatalog_noTenantInContext_badRequest() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));

        StepVerifier.create(service.updateCatalog(Set.of("A")))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.BAD_REQUEST))
                .verify();

        verifyNothingWritten();
    }

    /**
     * ES-03: delivery modes declared for a ccid outside enabledConfigurationIds are
     * rejected with InvalidDeliveryConfigException, and nothing is persisted.
     */
    @Test
    void updateCatalog_mapKeyNotInEnabledIds_rejectsWithoutPersisting() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B")));

        StepVerifier.create(service.updateCatalog(Set.of("A"), Map.of("B", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(InvalidDeliveryConfigException.class)
                .verify();

        verifyNothingWritten();
    }

    /**
     * AC-04, migrated from the retired TenantDeliveryConfigServiceImplTest
     * (setEligibleModes_directOnBoundType_rejectsWithoutTouchingTheRepository, R-9):
     * a mode outside the schema ceiling is rejected before any write -- not even the
     * other declared type persists.
     */
    @Test
    void updateCatalog_directOnBoundType_rejectsWithoutPersistingAnyDeclaredType() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B")));
        doThrow(new DeliveryModeNotEligibleException("direct not eligible for A"))
                .when(schemaDeliveryCeiling).validateWithinCeiling(eq("A"), any());

        StepVerifier.create(service.updateCatalog(
                        Set.of("A", "B"),
                        Map.of("A", Set.of(DeliveryMode.DIRECT), "B", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(DeliveryModeNotEligibleException.class)
                .verify();

        verifyNothingWritten();
    }

    /**
     * A type without an entry gets one, enabled, with the declared modes (EC-08: a set, so no duplicates)
     * and the validity and subject of its type file.
     */
    @Test
    void updateCatalog_typeWithoutEntry_insertsAnEnabledEntryFilledFromItsTypeFile() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));

        StepVerifier.create(service.updateCatalog(Set.of("A"), Map.of("A", Set.of(DeliveryMode.UI, DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        ArgumentCaptor<CatalogEntry> inserted = ArgumentCaptor.forClass(CatalogEntry.class);
        verify(catalogEntryPort).insert(inserted.capture());
        assertThat(inserted.getValue().credentialConfigurationId()).isEqualTo("A");
        assertThat(inserted.getValue().enabled()).isTrue();
        assertThat(inserted.getValue().deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
        assertThat(inserted.getValue().validity()).isNotNull();
        assertThat(inserted.getValue().isFilled()).isTrue();
        verify(catalogEntryPort, never()).updateIfVersion(any(), anyLong());
    }

    @Test
    void updateCatalog_typeWithoutEntryAndWithoutModes_insertsItWithTheSchemaCeiling() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(schemaDeliveryCeiling.resolveEligibleModes("A")).thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        ArgumentCaptor<CatalogEntry> inserted = ArgumentCaptor.forClass(CatalogEntry.class);
        verify(catalogEntryPort).insert(inserted.capture());
        assertThat(inserted.getValue().deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
    }

    /** D10: the alias creates rows too, so it refuses a type that needs a binding the catalog cannot offer. */
    @Test
    void updateCatalog_typeWithoutEntryThatNeedsAnUnsupportedBinding_failsWithoutInserting() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(registry.bindingTypeOf("A")).thenReturn(BindingType.CLAIM);
        when(registry.schemaUriOf("A")).thenReturn("https://registry.eudistack.net/schemas/A");

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(UnsupportedBindingTypeException.class)
                .verify();

        verify(catalogEntryPort, never()).insert(any());
    }

    /** EC-01: a ccid enabled but absent from the delivery-modes map keeps the modes already stored. */
    @Test
    void updateCatalog_omittingModesMapEntry_keepsTheStoredModes() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(stored("A", false, 3, DeliveryMode.EMAIL)));

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        CatalogEntry updated = updatedEntry(3);
        assertThat(updated.enabled()).isTrue();
        assertThat(updated.deliveryModes()).containsExactly(DeliveryMode.EMAIL);
        verify(catalogEntryPort, never()).insert(any());
    }

    @Test
    void updateCatalog_declaredModes_replaceTheStoredOnes() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(stored("A", true, 0, DeliveryMode.EMAIL)));

        StepVerifier.create(service.updateCatalog(Set.of("A"), Map.of("A", Set.of(DeliveryMode.UI)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        assertThat(updatedEntry(0).deliveryModes()).containsExactly(DeliveryMode.UI);
    }

    /** An entry saved with an explicit empty list (only a disabled one can be) reopens to the ceiling, never to nothing. */
    @Test
    void updateCatalog_enablingAnEntryStoredWithoutModes_reopensItToTheSchemaCeiling() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(schemaDeliveryCeiling.resolveEligibleModes("A")).thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(stored("A", false, 5)));

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        assertThat(updatedEntry(5).deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
    }

    /** D5: a type left out of the list is disabled, its row and everything configured on it stay. */
    @Test
    void updateCatalog_typeLeftOut_isDisabledNotDeleted() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B")));
        CatalogEntry a = stored("A", true, 2, DeliveryMode.EMAIL);
        CatalogEntry b = stored("B", true, 7, DeliveryMode.UI);
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(a, b));

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        CatalogEntry disabled = updatedEntry(7);
        assertThat(disabled.credentialConfigurationId()).isEqualTo("B");
        assertThat(disabled.enabled()).isFalse();
        assertThat(disabled).isEqualTo(b.withEnabled(false));
        verify(catalogEntryPort, times(1)).updateIfVersion(any(), anyLong());
    }

    /** At service level the empty set is the reset primitive: it disables everything, it deletes nothing. */
    @Test
    void updateCatalog_emptySet_disablesEveryEnabledEntry() {
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(
                stored("A", true, 1, DeliveryMode.EMAIL), stored("B", false, 4, DeliveryMode.UI),
                stored("C", true, 0, DeliveryMode.UI)));

        StepVerifier.create(service.updateCatalog(Set.of())
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        ArgumentCaptor<CatalogEntry> updated = ArgumentCaptor.forClass(CatalogEntry.class);
        verify(catalogEntryPort, times(2)).updateIfVersion(updated.capture(), anyLong());
        assertThat(updated.getAllValues()).extracting(CatalogEntry::credentialConfigurationId).containsExactly("A", "C");
        assertThat(updated.getAllValues()).allSatisfy(entry -> assertThat(entry.enabled()).isFalse());
        verify(catalogEntryPort, never()).insert(any());
    }

    /** EC-03: applying the same set twice writes nothing the second time, so the version is not bumped for nothing. */
    @Test
    void updateCatalog_reappliedWithSameValue_isIdempotent() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(stored("A", true, 1, DeliveryMode.EMAIL)));

        StepVerifier.create(service.updateCatalog(Set.of("A"), Map.of("A", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verifyNothingWritten();
    }

    /** D13: an entry the platform seeded with only its id is completed in the same write that enables it. */
    @Test
    void updateCatalog_entryNotFilledYet_isCompletedFromTheTypeFileWhenItIsWritten() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(schemaDeliveryCeiling.resolveEligibleModes("A")).thenReturn(EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(
                new CatalogEntry("A", null, true, null, null, null, List.of(), 0, Instant.now(), Instant.now())));

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        CatalogEntry updated = updatedEntry(0);
        assertThat(updated.isFilled()).isTrue();
        assertThat(updated.deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
    }

    /** Another write got to the entry between the read and the update: the whole replacement runs again. */
    @Test
    void updateCatalog_entryChangedConcurrently_retriesFromTheRead() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAll())
                .thenReturn(Flux.just(stored("A", false, 1, DeliveryMode.EMAIL)))
                .thenReturn(Flux.just(stored("A", false, 2, DeliveryMode.EMAIL)));
        // doReturn: the default answer of setUp must not run against the matchers
        doReturn(Mono.just(Optional.empty())).when(catalogEntryPort).updateIfVersion(any(), eq(1L));

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        verify(catalogEntryPort, times(2)).findAll();
        verify(catalogEntryPort).updateIfVersion(any(), eq(2L));
    }

    @Test
    void updateCatalog_entryCreatedConcurrently_retriesAndUpdatesIt() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAll())
                .thenReturn(Flux.empty())
                .thenReturn(Flux.just(stored("A", false, 0, DeliveryMode.EMAIL)));
        doReturn(Mono.error(new CatalogEntryAlreadyExistsException("A", new RuntimeException())))
                .when(catalogEntryPort).insert(any());

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        assertThat(updatedEntry(0).enabled()).isTrue();
    }

    // ---- audit of the entries the alias changes (AC-12): one event per entry, none for an untouched one ----

    @Test
    void updateCatalog_auditsOneChangePerEntryWritten_afterCommit() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A"), "B", profile("B", "B"),
                "C", profile("C", "C"), "D", profile("D", "D")));
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(
                stored("A", true, 2, DeliveryMode.EMAIL),      // stays as it is
                stored("B", true, 7, DeliveryMode.UI),         // left out: disabled
                stored("C", false, 3, DeliveryMode.EMAIL)));   // listed: enabled
        // D has no entry: created

        StepVerifier.create(service.updateCatalog(Set.of("A", "C", "D"), Map.of("A", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        List<CatalogEntryChange> changes = auditedChanges();
        assertThat(changes).extracting(CatalogEntryChange::credentialConfigurationId, CatalogEntryChange::action)
                .containsExactlyInAnyOrder(
                        tuple("B", CatalogEntryChange.Action.DISABLE),
                        tuple("C", CatalogEntryChange.Action.ENABLE),
                        tuple("D", CatalogEntryChange.Action.CREATE));
        CatalogEntryChange disabled = changes.stream()
                .filter(c -> c.credentialConfigurationId().equals("B")).findFirst().orElseThrow();
        assertThat(disabled.changes()).containsOnlyKeys("enabled");
        assertThat(disabled.before().version()).isEqualTo(7);
    }

    @Test
    void updateCatalog_reappliedWithSameValue_auditsNothing() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAll()).thenReturn(Flux.just(stored("A", true, 1, DeliveryMode.EMAIL)));

        StepVerifier.create(service.updateCatalog(Set.of("A"), Map.of("A", Set.of(DeliveryMode.EMAIL)))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        assertThat(auditedChanges()).isEmpty();
    }

    @Test
    void updateCatalog_entryChangedConcurrently_auditsOnlyTheWriteThatCommitted() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAll())
                .thenReturn(Flux.just(stored("A", false, 1, DeliveryMode.EMAIL)))
                .thenReturn(Flux.just(stored("A", false, 2, DeliveryMode.EMAIL)));
        doReturn(Mono.just(Optional.empty())).when(catalogEntryPort).updateIfVersion(any(), eq(1L));

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .verifyComplete();

        assertThat(auditedChanges()).hasSize(1);
        assertThat(auditedChanges().getFirst().before().version()).isEqualTo(2);
    }

    @Test
    void updateCatalog_writeFails_auditsNothing() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        doReturn(Mono.error(new RuntimeException("db down"))).when(catalogEntryPort).insert(any());

        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(RuntimeException.class)
                .verify();

        verify(changeAuditor, never()).auditAll(any());
    }

    @Test
    void updateCatalog_success_invalidatesCache() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A")));

        // Prime the cache for TENANT.
        service.getEnabledConfigurationIds()
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
        // Successful write must invalidate it.
        service.updateCatalog(Set.of("A"))
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
        // Reading again must hit the repository once more (cache was invalidated).
        service.getEnabledConfigurationIds()
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();

        verify(catalogEntryPort, times(2)).findAllByEnabled(true);
    }

    @Test
    void updateCatalog_writeFails_doesNotInvalidateCache() {
        when(registry.getAllProfiles()).thenReturn(Map.of("A", profile("A", "A")));
        doReturn(Mono.error(new RuntimeException("db down"))).when(catalogEntryPort).insert(any());
        when(catalogEntryPort.findAllByEnabled(true)).thenReturn(Flux.just(row("A")));

        // Prime the cache.
        service.getEnabledConfigurationIds()
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();
        // Failing write must NOT invalidate the cache.
        StepVerifier.create(service.updateCatalog(Set.of("A"))
                        .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(RuntimeException.class)
                .verify();
        // Cache still warm → repository not queried again.
        service.getEnabledConfigurationIds()
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();

        verify(catalogEntryPort, times(1)).findAllByEnabled(true);
    }

    // ---- helpers --------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private List<CatalogEntryChange> auditedChanges() {
        ArgumentCaptor<List<CatalogEntryChange>> changes = ArgumentCaptor.forClass(List.class);
        verify(changeAuditor).auditAll(changes.capture());
        return changes.getValue();
    }

    private void verifyNothingWritten() {
        verify(catalogEntryPort, never()).insert(any());
        verify(catalogEntryPort, never()).updateIfVersion(any(), anyLong());
    }

    /** The single entry written with {@code updateIfVersion} against {@code expectedVersion}. */
    private CatalogEntry updatedEntry(long expectedVersion) {
        ArgumentCaptor<CatalogEntry> updated = ArgumentCaptor.forClass(CatalogEntry.class);
        verify(catalogEntryPort).updateIfVersion(updated.capture(), eq(expectedVersion));
        return updated.getValue();
    }

    /**
     * A filled entry as the adapter returns it: validity from a type file and, when it is not enabled,
     * whatever {@code modes} it was saved with (none = an explicit empty list).
     */
    private static CatalogEntry stored(String configId, boolean enabled, long version, DeliveryMode... modes) {
        return new CatalogEntry(configId, null, enabled, Set.of(modes), new CatalogEntry.Validity(365, true, 365),
                null, List.of(), version, Instant.parse("2026-10-19T08:00:00Z"), Instant.parse("2026-10-19T08:00:00Z"));
    }

    private static CredentialCatalogEntryDto entry(List<CredentialCatalogEntryDto> list, String id) {
        return list.stream().filter(e -> e.credentialConfigurationId().equals(id)).findFirst().orElseThrow();
    }

    private static CatalogEntry row(String configId) {
        return row(configId, null);
    }

    /** An enabled entry; {@code deliveryModes} is the canonical CSV, {@code null} = row not filled yet. */
    private static CatalogEntry row(String configId, String deliveryModes) {
        return new CatalogEntry(configId, null, true,
                deliveryModes == null ? null : DeliveryMode.parse(deliveryModes),
                null, null, List.of(), 0, Instant.now(), Instant.now());
    }

    private static CredentialProfile profile(String id, String displayName) {
        var builder = CredentialProfile.builder().credentialConfigurationId(id);
        if (displayName != null) {
            builder.credentialMetadata(CredentialProfile.CredentialMetadata.builder()
                    .display(List.of(CredentialProfile.DisplayInfo.builder().name(displayName).build()))
                    .build());
        }
        return builder.build();
    }
}
