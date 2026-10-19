package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException;
import es.in2.issuer.backend.shared.domain.exception.PreconditionFailedException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.SearchIdentifierInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.SubjectInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogConfigurationInput.ValidityInput;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntryETag;
import es.in2.issuer.backend.shared.domain.model.catalog.CreateCatalogEntryCommand;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireCredentialProfileAllowedForTenantRule;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import es.in2.issuer.backend.support.TenantSchemaMigrations;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Signal;
import reactor.core.scheduler.Schedulers;
import reactor.util.context.Context;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.support.TenantSchemaMigrations.schemaOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link AttestationCatalogService} against a real Postgres, in a tenant schema of its own: the
 * optimistic lock of FR-05 (AC-07), the unique violations of simultaneous creates (AC-03), and what a
 * disabled entry stops being for OID4VCI metadata and issuance (AC-08, AC-09) now that the cache holds
 * catalog entries.
 */
class AttestationCatalogConcurrencyIT extends PostgresIntegrationBase {

    private static final String TENANT = "catalog-concurrency";
    private static final String DOCTORID = "doctorid.sd.1";
    private static final String DOCTORID_URI = "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt";
    private static final String LEAR = "learcredential.employee.sd.1";
    private static final String LEAR_SYNTHETIC_URI = "https://registry.eudistack.net/schemas/" + LEAR;

    @DynamicPropertySource
    static void useCatalogProfiles(DynamicPropertyRegistry registry) {
        registry.add("credential.profiles.path", () -> "classpath:catalog-profiles");
    }

    @Autowired private AttestationCatalogService service;
    @Autowired private TenantCredentialProfileService tenantCredentialProfileService;
    @Autowired private CredentialIssuerMetadataService metadataService;
    @Autowired private RequireCredentialProfileAllowedForTenantRule credentialProfileAllowedRule;

    @BeforeAll
    static void migrateTenantSchema(@Autowired FlywayProperties flywayProperties,
                                    @Autowired R2dbcProperties r2dbcProperties) {
        TenantSchemaMigrations.migrate(flywayProperties, r2dbcProperties, TENANT, null);
    }

    @BeforeEach
    void emptyCatalog() {
        databaseClient.sql("DELETE FROM \"" + schemaOf(TENANT) + "\".tenant_credential_profile").then().block();
        tenantCredentialProfileService.invalidateCache(TENANT);
    }

    // ---- AC-07: optimistic concurrency -----------------------------------------

    @Test
    void replace_twiceWithTheSameETag_theSecondIsPreconditionFailed() {
        CatalogEntry created = inTenant(service.create(doctorIdCreate(true))).block();
        String eTag = CatalogEntryETag.of(created);

        CatalogEntry first = inTenant(service.replace(DOCTORID, doctorId(true, 100), eTag)).block();

        assertThat(first.version()).isEqualTo(created.version() + 1);
        assertThatThrownBy(() -> inTenant(service.replace(DOCTORID, doctorId(true, 200), eTag)).block())
                .isInstanceOf(PreconditionFailedException.class);
        assertThat(inTenant(service.get(DOCTORID)).block().validity().defaultDays()).isEqualTo(100);
    }

    @Test
    void replace_simultaneouslyWithTheSameETag_exactlyOneWins() {
        CatalogEntry created = inTenant(service.create(doctorIdCreate(true))).block();
        String eTag = CatalogEntryETag.of(created);

        List<Signal<CatalogEntry>> outcomes = Mono.zip(
                        inTenant(service.replace(DOCTORID, doctorId(true, 100), eTag)).subscribeOn(Schedulers.boundedElastic()).materialize(),
                        inTenant(service.replace(DOCTORID, doctorId(true, 200), eTag)).subscribeOn(Schedulers.boundedElastic()).materialize())
                .map(pair -> List.of(pair.getT1(), pair.getT2()))
                .block();

        assertThat(outcomes).filteredOn(Signal::hasValue).hasSize(1);
        assertThat(outcomes).filteredOn(Signal::hasError).hasSize(1)
                .allSatisfy(signal -> assertThat(signal.getThrowable()).isInstanceOf(PreconditionFailedException.class));
        assertThat(inTenant(service.get(DOCTORID)).block().version()).isEqualTo(created.version() + 1);
    }

    // ---- AC-03: unique violations ----------------------------------------------

    @Test
    void create_simultaneouslyOfASchemaWithADeclaredSchemaUri_theSecondIsCatalogEntryAlreadyExists() {
        assertExactlyOneOfTwoSimultaneousCreatesWins(doctorIdCreate(true));
        assertThat(storedSchemaUri(DOCTORID)).isEqualTo(DOCTORID_URI);
    }

    @Test
    void create_simultaneouslyOfASchemaWithoutDeclaredSchemaUri_theSecondIsCatalogEntryAlreadyExists() {
        assertExactlyOneOfTwoSimultaneousCreatesWins(new CreateCatalogEntryCommand(LEAR_SYNTHETIC_URI,
                doctorId(true, 36500, null, List.of())));
        assertThat(storedSchemaUri(LEAR)).as("the synthetic URI is never stored").isNull();
    }

    @Test
    void create_ofASchemaUriAlreadyTakenByAnotherEntry_isCatalogEntryAlreadyExists() {
        databaseClient.sql("INSERT INTO \"" + schemaOf(TENANT) + "\".tenant_credential_profile "
                        + "(credential_configuration_id, schema_uri) VALUES ('other.type', '" + DOCTORID_URI + "')")
                .then().block();

        assertThatThrownBy(() -> inTenant(service.create(doctorIdCreate(true))).block())
                .isInstanceOf(CatalogEntryAlreadyExistsException.class);
    }

    // ---- AC-08, AC-09: disabling an entry --------------------------------------

    @Test
    void setEnabled_false_removesTheEntryFromTheMetadataAndIssuanceIsRejected() {
        CatalogEntry created = inTenant(service.create(doctorIdCreate(true))).block();
        // Warm the cache of this instance: the disable has to invalidate it.
        assertThat(advertisedConfigurations()).contains(DOCTORID);
        assertThat(isAllowedToIssue(DOCTORID)).isTrue();

        CatalogEntry disabled = inTenant(service.setEnabled(DOCTORID, false, CatalogEntryETag.of(created))).block();

        assertThat(disabled.enabled()).isFalse();
        assertThat(advertisedConfigurations()).doesNotContain(DOCTORID);
        assertThat(isAllowedToIssue(DOCTORID)).isFalse();
        assertThatThrownBy(() -> inTenant(credentialProfileAllowedRule.evaluate(null, DOCTORID)).block())
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("is not enabled for this tenant");
        assertThat(inTenant(service.list(true).collectList()).block()).isEmpty();
        assertThat(inTenant(service.get(DOCTORID)).block().enabled()).as("the entry is kept").isFalse();
    }

    @Test
    void setEnabled_true_makesTheEntryAvailableAgain() {
        CatalogEntry created = inTenant(service.create(doctorIdCreate(false))).block();
        assertThat(advertisedConfigurations()).doesNotContain(DOCTORID);

        inTenant(service.setEnabled(DOCTORID, true, CatalogEntryETag.of(created))).block();

        assertThat(advertisedConfigurations()).contains(DOCTORID);
        assertThat(isAllowedToIssue(DOCTORID)).isTrue();
    }

    @Test
    void replace_disablingTheEntry_alsoStopsItBeingAdvertised() {
        CatalogEntry created = inTenant(service.create(doctorIdCreate(true))).block();
        assertThat(advertisedConfigurations()).contains(DOCTORID);

        inTenant(service.replace(DOCTORID, doctorId(false, 36500), CatalogEntryETag.of(created))).block();

        assertThat(advertisedConfigurations()).doesNotContain(DOCTORID);
    }

    // ---- helpers ---------------------------------------------------------------

    private void assertExactlyOneOfTwoSimultaneousCreatesWins(CreateCatalogEntryCommand command) {
        List<Signal<CatalogEntry>> outcomes = Mono.zip(
                        inTenant(service.create(command)).subscribeOn(Schedulers.boundedElastic()).materialize(),
                        inTenant(service.create(command)).subscribeOn(Schedulers.boundedElastic()).materialize())
                .map(pair -> List.of(pair.getT1(), pair.getT2()))
                .block();

        assertThat(outcomes).filteredOn(Signal::hasValue).hasSize(1);
        assertThat(outcomes).filteredOn(Signal::hasError).hasSize(1)
                .allSatisfy(signal -> assertThat(signal.getThrowable()).isInstanceOf(CatalogEntryAlreadyExistsException.class));
    }

    private Set<String> advertisedConfigurations() {
        return inTenant(metadataService.getCredentialIssuerMetadata("http://localhost/issuer")).block()
                .credentialConfigurationsSupported().keySet();
    }

    private boolean isAllowedToIssue(String credentialConfigurationId) {
        return Boolean.TRUE.equals(inTenant(tenantCredentialProfileService.isProfileAllowed(credentialConfigurationId)).block());
    }

    private String storedSchemaUri(String credentialConfigurationId) {
        return databaseClient.sql("SELECT schema_uri FROM \"" + schemaOf(TENANT)
                        + "\".tenant_credential_profile WHERE credential_configuration_id = :id")
                .bind("id", credentialConfigurationId)
                .map(row -> Optional.ofNullable(row.get("schema_uri", String.class)))
                .one().block().orElse(null);
    }

    private static <T> Mono<T> inTenant(Mono<T> mono) {
        return mono.contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private static <T> Flux<T> inTenant(Flux<T> flux) {
        return flux.contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private static CreateCatalogEntryCommand doctorIdCreate(boolean enabled) {
        return new CreateCatalogEntryCommand(DOCTORID_URI, doctorId(enabled, 36500));
    }

    private static CatalogConfigurationInput doctorId(boolean enabled, int defaultDays) {
        return doctorId(enabled, defaultDays, new SubjectInput(
                List.of(List.of("givenName"), List.of("familyName")), " ", null),
                List.of(new SearchIdentifierInput("colegiado", List.of("personal_administrative_number"), null)));
    }

    private static CatalogConfigurationInput doctorId(boolean enabled, int defaultDays, SubjectInput subject,
                                                      List<SearchIdentifierInput> identifiers) {
        return new CatalogConfigurationInput(enabled, List.of("email", "ui"),
                new ValidityInput(defaultDays, false, null, null), subject, identifiers, null);
    }
}
