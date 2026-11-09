package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.shared.domain.exception.CredentialCatalogNotConfiguredException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialCatalogEntryDto;
import es.in2.issuer.backend.shared.domain.model.entities.TenantCredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.repository.TenantCredentialProfileRepository;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;
import reactor.util.context.ContextView;

import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves that reactive transactions ({@link TransactionalOperator}) work correctly on
 * top of the schema-per-tenant {@code TenantAwareConnectionFactoryDecorator} (EUD-72,
 * risk R-2). This is the first reactive transaction exercised in the Issuer, so it
 * verifies four things end-to-end against a real Postgres:
 *
 * <ol>
 *   <li>a committed {@code updateCatalog} lands in the current tenant's schema and is
 *       readable back;</li>
 *   <li>writes are isolated between tenants (search_path honored inside the transaction);</li>
 *   <li>an error mid-transaction rolls back the {@code deleteAll}, leaving the prior
 *       state intact — the failure mode that would otherwise wipe the tenant catalog and
 *       leave it unable to issue;</li>
 *   <li>re-applying the same set is idempotent (EC-03).</li>
 * </ol>
 *
 * <p>Since EUD-266 (D5) {@code updateCatalog} disables the types it leaves out instead of deleting them,
 * so the tests clear the tenants with the repository, and the rows of disabled types are asserted
 * through {@link CatalogEntryPort}.
 */
class CredentialCatalogTransactionalIT extends PostgresIntegrationBase {

    private static final String TENANT_A = "e2e-tenant-a";
    private static final String TENANT_B = "e2e-tenant-b";

    // Second real profile fixture (TD-2/TD-4): a distinct, unbound credential type so
    // ES-04/ES-10 can exercise a genuinely mixed multi-type payload against a real
    // Postgres instead of only against the one bound fixture that used to be alone on
    // this classpath (src/test/resources/credentials/profiles).
    private static final String SECOND_CONFIG_ID = "gx.labelcredential.w3c.2";

    @Autowired private TenantCredentialProfileService service;
    @Autowired private TenantCredentialProfileRepository repository;
    @Autowired private CatalogEntryPort catalogEntryPort;
    @Autowired private TransactionalOperator transactionalOperator;
    @Autowired private R2dbcEntityTemplate r2dbcEntityTemplate;
    @Autowired private CredentialProfileRegistry registry;

    private String configId;

    @BeforeEach
    void resetTenants() {
        List<String> ids = List.copyOf(registry.getAllProfiles().keySet());
        assertThat(ids).as("registry must expose at least one credential profile").isNotEmpty();
        assertThat(registry.getByConfigurationId(SECOND_CONFIG_ID))
                .as("registry must expose the second fixture (%s) used by ES-04/ES-10 multi-type tests", SECOND_CONFIG_ID)
                .isNotNull();
        // Exclude SECOND_CONFIG_ID explicitly rather than trusting registry iteration order --
        // it must never equal configId (Set.of(configId, SECOND_CONFIG_ID) below would throw
        // IllegalArgumentException: duplicate element if it did).
        configId = ids.stream().filter(id -> !id.equals(SECOND_CONFIG_ID)).findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "registry must expose a profile distinct from " + SECOND_CONFIG_ID));
        // Clear both tenant schemas: updateCatalog no longer deletes, so empty them directly.
        for (String tenant : List.of(TENANT_A, TENANT_B)) {
            repository.deleteAll().contextWrite(ctx(tenant)).block();
            service.invalidateCache(tenant);
        }
    }

    @Test
    void updateCatalog_committedWrite_isReadableBackFromTenantSchema() {
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactly(configId);

        List<CredentialCatalogEntryDto> catalog =
                service.getCatalog().contextWrite(ctx(TENANT_A)).block();
        assertThat(catalog).isNotNull();
        assertThat(entry(catalog).enabled()).isTrue();
    }

    @Test
    void updateCatalog_isolatedBetweenTenants() {
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();
        // TENANT_B left empty by resetTenants().

        List<TenantCredentialProfile> rowsA =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        List<TenantCredentialProfile> rowsB =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_B)).block();

        assertThat(rowsA).hasSize(1);
        assertThat(rowsB).isEmpty();

        // B never configured → nothing enabled → the catalog read is a 404, not an empty view.
        StepVerifier.create(service.getCatalog().contextWrite(ctx(TENANT_B)))
                .expectError(CredentialCatalogNotConfiguredException.class)
                .verify();
    }

    /**
     * EC-03: saving the same selection twice must be a no-op seen from outside: no duplicated
     * row, no changed verdict, and no version bump for a write that changed nothing; the stored
     * rows, the catalog projection and the version are asserted.
     */
    @Test
    void updateCatalog_appliedTwiceWithSameSet_isIdempotent() {
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();
        List<CredentialCatalogEntryDto> afterFirst =
                service.getCatalog().contextWrite(ctx(TENANT_A)).block();

        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();
        List<CredentialCatalogEntryDto> afterSecond =
                service.getCatalog().contextWrite(ctx(TENANT_A)).block();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactly(configId);
        assertThat(afterFirst).isNotNull();
        assertThat(afterSecond).isEqualTo(afterFirst);
        assertThat(entryOf(TENANT_A, configId).version()).isZero();
    }

    @Test
    void transactionalWrite_rollsBackOnError_leavingPreviousStateIntact() {
        // Committed baseline for tenant A.
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        Instant now = Instant.now();
        Mono<Void> failingTx = transactionalOperator.transactional(
                repository.deleteAll()
                        .then(r2dbcEntityTemplate.insert(
                                new TenantCredentialProfile(null, configId, true, now, now, null)).then())
                        .then(Mono.<Void>error(new RuntimeException("boom")))
        ).contextWrite(ctx(TENANT_A));

        StepVerifier.create(failingTx).expectError(RuntimeException.class).verify();

        // deleteAll must have been rolled back → baseline row still present.
        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactly(configId);
    }

    /**
     * EC-01: a write that omits a type's delivery-modes entry entirely preserves whatever
     * is already stored -- the engine-side COALESCE in the UPSERT (task 6), not a
     * read-modify-write.
     */
    @Test
    void updateCatalog_omittingModesField_preservesStoredModes() {
        service.updateCatalog(Set.of(configId), Map.of(configId, EnumSet.of(DeliveryMode.EMAIL)))
                .contextWrite(ctx(TENANT_A)).block();

        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        Set<DeliveryMode> configured = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(TENANT_A)).block();
        assertThat(configured).containsExactly(DeliveryMode.EMAIL);
    }

    /**
     * EC-02, changed by EUD-266 (D5): disabling a type keeps its row, with everything configured on it, and
     * bumps its version. Re-enabling it without declaring modes keeps the stored ones (EC-01) instead of
     * reopening the type to the schema ceiling.
     */
    @Test
    void disablingType_keepsItsRowDisabledWithItsModes_andReEnablingKeepsThem() {
        service.updateCatalog(Set.of(configId), Map.of(configId, EnumSet.of(DeliveryMode.EMAIL)))
                .contextWrite(ctx(TENANT_A)).block();
        assertThat(entryOf(TENANT_A, configId).version()).isZero();

        service.updateCatalog(Set.of()).contextWrite(ctx(TENANT_A)).block();

        List<TenantCredentialProfile> enabledAfterDisable =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(enabledAfterDisable).isEmpty();
        CatalogEntry disabled = entryOf(TENANT_A, configId);
        assertThat(disabled.enabled()).isFalse();
        assertThat(disabled.deliveryModes()).containsExactly(DeliveryMode.EMAIL);
        assertThat(disabled.version()).isEqualTo(1);

        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();
        Set<DeliveryMode> configuredAfterReEnable = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(TENANT_A)).block();
        assertThat(configuredAfterReEnable).containsExactly(DeliveryMode.EMAIL);
        assertThat(entryOf(TENANT_A, configId).version()).isEqualTo(2);
    }

    /** The empty set at service level disables every entry; a disabled one cannot be issued, nor is it advertised. */
    @Test
    void updateCatalog_emptySet_disablesEveryEntryAndRemovesThemFromWhatIsEnabled() {
        service.updateCatalog(Set.of(configId, SECOND_CONFIG_ID)).contextWrite(ctx(TENANT_A)).block();

        service.updateCatalog(Set.of()).contextWrite(ctx(TENANT_A)).block();

        assertThat(service.getEnabledConfigurationIds().contextWrite(ctx(TENANT_A)).block()).isEmpty();
        assertThat(entriesOf(TENANT_A)).hasSize(2).allSatisfy(entry -> assertThat(entry.enabled()).isFalse());
        StepVerifier.create(service.getCatalog().contextWrite(ctx(TENANT_A)))
                .expectError(CredentialCatalogNotConfiguredException.class)
                .verify();
    }

    /** What the portal sees: a disabled type is listed with enabled=false, as before, while another is enabled. */
    @Test
    void getCatalog_aTypeDisabledByUpdateCatalog_isStillListedAsDisabled() {
        service.updateCatalog(Set.of(configId, SECOND_CONFIG_ID)).contextWrite(ctx(TENANT_A)).block();

        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        List<CredentialCatalogEntryDto> catalog = service.getCatalog().contextWrite(ctx(TENANT_A)).block();
        assertThat(catalog).filteredOn(e -> e.credentialConfigurationId().equals(configId))
                .singleElement().satisfies(e -> assertThat(e.enabled()).isTrue());
        assertThat(catalog).filteredOn(e -> e.credentialConfigurationId().equals(SECOND_CONFIG_ID))
                .singleElement().satisfies(e -> assertThat(e.enabled()).isFalse());
    }

    /** D5: a row the alias creates is filled on insert, so the attestation catalog API can show it. */
    @Test
    void updateCatalog_newType_createsAFilledEntryAtVersionZero() {
        service.updateCatalog(Set.of(configId)).contextWrite(ctx(TENANT_A)).block();

        CatalogEntry entry = entryOf(TENANT_A, configId);

        assertThat(entry.isFilled()).isTrue();
        assertThat(entry.deliveryModes()).isNotEmpty();
        assertThat(entry.version()).isZero();
    }

    /**
     * EC-03 (with modes): reapplying the same delivery-modes configuration twice is a
     * no-op -- one row, same canonical value, no error.
     */
    @Test
    void updateCatalog_reappliedWithSameModes_isIdempotent() {
        Map<String, Set<DeliveryMode>> modes = Map.of(configId, EnumSet.of(DeliveryMode.EMAIL, DeliveryMode.UI));

        service.updateCatalog(Set.of(configId), modes).contextWrite(ctx(TENANT_A)).block();
        service.updateCatalog(Set.of(configId), modes).contextWrite(ctx(TENANT_A)).block();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).hasSize(1);
        assertThat(rows.getFirst().deliveryModes()).isEqualTo("email,ui");
    }

    /**
     * ES-04: two overlapping writes for the same tenant, fired concurrently (Flux.merge
     * subscribes to both eagerly, unlike sequential blocking), must leave a single
     * coherent row -- never a duplicate or partially-written one -- regardless of which
     * one's delivery-modes value ultimately wins the race.
     */
    @Test
    void concurrentUpdates_sameTenant_leaveNoDuplicateRowsAndPreservesUntouchedType() {
        // Seed both types enabled; SECOND_CONFIG_ID starts with modes already configured.
        service.updateCatalog(Set.of(configId, SECOND_CONFIG_ID),
                        Map.of(SECOND_CONFIG_ID, EnumSet.of(DeliveryMode.UI)))
                .contextWrite(ctx(TENANT_A)).block();

        // Neither concurrent write below declares modes for SECOND_CONFIG_ID (ES-04: "el
        // sistema MUST NOT perder los modos de entrega de los tipos que ninguna de las dos
        // declaró") -- its stored modes must survive both, regardless of interleaving.
        Mono<Void> writeDeclaringModes = service.updateCatalog(
                        Set.of(configId, SECOND_CONFIG_ID), Map.of(configId, EnumSet.of(DeliveryMode.EMAIL)))
                .contextWrite(ctx(TENANT_A));
        Mono<Void> writePreservingModes = service.updateCatalog(Set.of(configId, SECOND_CONFIG_ID))
                .contextWrite(ctx(TENANT_A));

        Flux.merge(writeDeclaringModes, writePreservingModes).blockLast();

        List<TenantCredentialProfile> rows =
                repository.findAllByEnabledTrue().collectList().contextWrite(ctx(TENANT_A)).block();
        assertThat(rows).hasSize(2);
        assertThat(rows).extracting(TenantCredentialProfile::credentialConfigurationId)
                .containsExactlyInAnyOrder(configId, SECOND_CONFIG_ID);
        assertThat(rows).filteredOn(r -> r.credentialConfigurationId().equals(SECOND_CONFIG_ID))
                .extracting(TenantCredentialProfile::deliveryModes)
                .containsExactly("ui");
    }

    /**
     * AC-06 / NFR-S-169-04: delivery modes stored for the same credential_configuration_id
     * never leak between tenants.
     */
    @Test
    void deliveryModes_areIsolatedBetweenTenants() {
        service.updateCatalog(Set.of(configId), Map.of(configId, EnumSet.of(DeliveryMode.EMAIL)))
                .contextWrite(ctx(TENANT_A)).block();
        service.updateCatalog(Set.of(configId), Map.of(configId, EnumSet.of(DeliveryMode.UI)))
                .contextWrite(ctx(TENANT_B)).block();

        Set<DeliveryMode> configuredA = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(TENANT_A)).block();
        Set<DeliveryMode> configuredB = service.findConfiguredDeliveryModes(configId)
                .contextWrite(ctx(TENANT_B)).block();

        assertThat(configuredA).containsExactly(DeliveryMode.EMAIL);
        assertThat(configuredB).containsExactly(DeliveryMode.UI);
    }

    /**
     * AC-08: the retired parallel module's route no longer exists post-cutover. Bound
     * directly to the server port (not the {@code /issuer}-prefixed helper from the base
     * class, which is specific to the apiclient/oauth flows) since this path was never
     * under that prefix.
     */
    @Test
    void oldDeliveryConfigRoute_noLongerExists_returns404() {
        WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port)
                .build()
                .get().uri("/api/v1/backoffice/delivery-config/" + configId)
                .exchange()
                .expectStatus().isNotFound();
    }

    private CredentialCatalogEntryDto entry(List<CredentialCatalogEntryDto> catalog) {
        return catalog.stream()
                .filter(e -> e.credentialConfigurationId().equals(configId))
                .findFirst().orElseThrow();
    }

    private CatalogEntry entryOf(String tenant, String credentialConfigurationId) {
        return catalogEntryPort.findById(credentialConfigurationId).contextWrite(ctx(tenant)).block();
    }

    private List<CatalogEntry> entriesOf(String tenant) {
        return catalogEntryPort.findAll().collectList().contextWrite(ctx(tenant)).block();
    }

    private static ContextView ctx(String tenant) {
        return Context.of(TENANT_DOMAIN_CONTEXT_KEY, tenant);
    }
}
