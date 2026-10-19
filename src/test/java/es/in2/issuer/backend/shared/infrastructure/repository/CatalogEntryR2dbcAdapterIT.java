package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.exception.CatalogEntryAlreadyExistsException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import es.in2.issuer.backend.support.TenantSchemaMigrations;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.support.TenantSchemaMigrations.schemaOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@link CatalogEntryR2dbcAdapter} against a real Postgres, in a tenant schema of its own. */
class CatalogEntryR2dbcAdapterIT extends PostgresIntegrationBase {

    private static final String TENANT = "catalog-adapter";
    private static final String DOCTORID = "doctorid.sd.1";
    private static final String DOCTORID_URI = "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt";

    @Autowired private FlywayProperties flywayProperties;
    @Autowired private R2dbcProperties r2dbcProperties;
    @Autowired private CatalogEntryPort port;

    @BeforeAll
    static void migrateTenantSchema(@Autowired FlywayProperties flywayProperties,
                                    @Autowired R2dbcProperties r2dbcProperties) {
        TenantSchemaMigrations.migrate(flywayProperties, r2dbcProperties, TENANT, null);
    }

    @BeforeEach
    void emptyCatalog() {
        databaseClient.sql("DELETE FROM \"" + schemaOf(TENANT) + "\".tenant_credential_profile").then().block();
    }

    @Test
    void insert_persistsTheWholeConfiguration_andReturnsItAtVersionZero() {
        CatalogEntry stored = inTenant(port.insert(doctorId())).block();

        assertThat(stored.credentialConfigurationId()).isEqualTo(DOCTORID);
        assertThat(stored.schemaUri()).isEqualTo(DOCTORID_URI);
        assertThat(stored.enabled()).isTrue();
        assertThat(stored.deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
        assertThat(stored.validity()).isEqualTo(new CatalogEntry.Validity(36500, false, null));
        assertThat(stored.subject()).isEqualTo(new CatalogEntry.Subject(
                List.of(ClaimPath.of("givenName"), ClaimPath.of("familyName")), " "));
        assertThat(stored.searchIdentifiers()).containsExactly(
                new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("personal_administrative_number")));
        assertThat(stored.version()).isZero();
        assertThat(stored.created()).isNotNull();
        assertThat(stored.updated()).isNotNull();
    }

    @Test
    void insert_ofAnEntryWithoutSubjectAndWithRequesterDates_roundTripsThem() {
        CatalogEntry entry = new CatalogEntry("learcredential.employee.sd.1", null, false, Set.of(),
                new CatalogEntry.Validity(365, true, 730), null, List.of(), 0, null, null);

        CatalogEntry stored = inTenant(port.insert(entry)).block();

        assertThat(stored.schemaUri()).isNull();
        assertThat(stored.deliveryModes()).isEmpty();
        assertThat(stored.validity()).isEqualTo(new CatalogEntry.Validity(365, true, 730));
        assertThat(stored.subject()).isNull();
        assertThat(stored.searchIdentifiers()).isEmpty();
    }

    @Test
    void insert_ofTheSameCredentialConfigurationId_failsWithEntryAlreadyExists() {
        inTenant(port.insert(doctorId())).block();

        assertThatThrownBy(() -> inTenant(port.insert(doctorId())).block())
                .isInstanceOf(CatalogEntryAlreadyExistsException.class);
    }

    @Test
    void insert_ofTheSameSchemaUriUnderAnotherId_failsWithEntryAlreadyExists() {
        inTenant(port.insert(doctorId())).block();
        CatalogEntry sameSchema = withId(doctorId(), "doctorid.sd.2");

        assertThatThrownBy(() -> inTenant(port.insert(sameSchema)).block())
                .isInstanceOf(CatalogEntryAlreadyExistsException.class);
    }

    @Test
    void findById_returnsTheEntry_andEmptyWhenAbsent() {
        inTenant(port.insert(doctorId())).block();

        assertThat(inTenant(port.findById(DOCTORID)).block()).isNotNull();
        assertThat(inTenant(port.findById("unknown.type")).block()).isNull();
    }

    @Test
    void findAll_andFindAllByEnabled_filterByEnablement() {
        inTenant(port.insert(doctorId())).block();
        inTenant(port.insert(new CatalogEntry("gx.labelcredential.w3c.2", null, false, Set.of(),
                new CatalogEntry.Validity(365, false, null), null, List.of(), 0, null, null))).block();

        assertThat(inTenant(port.findAll().collectList()).block())
                .extracting(CatalogEntry::credentialConfigurationId)
                .containsExactly(DOCTORID, "gx.labelcredential.w3c.2");
        assertThat(inTenant(port.findAllByEnabled(true).collectList()).block())
                .extracting(CatalogEntry::credentialConfigurationId).containsExactly(DOCTORID);
        assertThat(inTenant(port.findAllByEnabled(false).collectList()).block())
                .extracting(CatalogEntry::credentialConfigurationId).containsExactly("gx.labelcredential.w3c.2");
    }

    @Test
    void updateIfVersion_withTheCurrentVersion_replacesTheConfigurationAndBumpsTheVersion() {
        CatalogEntry stored = inTenant(port.insert(doctorId())).block();
        CatalogEntry change = new CatalogEntry(DOCTORID, null, false, Set.of(DeliveryMode.UI),
                new CatalogEntry.Validity(365, true, 730), null, List.of(), 0, null, null);

        Optional<CatalogEntry> updated = inTenant(port.updateIfVersion(change, stored.version())).block();

        assertThat(updated).isPresent();
        CatalogEntry entry = updated.get();
        assertThat(entry.version()).isEqualTo(1);
        assertThat(entry.enabled()).isFalse();
        assertThat(entry.deliveryModes()).containsExactly(DeliveryMode.UI);
        assertThat(entry.validity()).isEqualTo(new CatalogEntry.Validity(365, true, 730));
        assertThat(entry.subject()).isNull();
        assertThat(entry.searchIdentifiers()).isEmpty();
        assertThat(entry.schemaUri()).as("the stored schema URI never changes").isEqualTo(DOCTORID_URI);
        assertThat(entry.created()).isEqualTo(stored.created());
        assertThat(entry.updated()).isAfterOrEqualTo(stored.updated());
    }

    @Test
    void updateIfVersion_withAStaleVersion_changesNothing() {
        CatalogEntry stored = inTenant(port.insert(doctorId())).block();
        inTenant(port.updateIfVersion(doctorId(), stored.version())).block();

        Optional<CatalogEntry> second = inTenant(port.updateIfVersion(
                new CatalogEntry(DOCTORID, null, false, Set.of(DeliveryMode.UI),
                        new CatalogEntry.Validity(1, false, null), null, List.of(), 0, null, null),
                stored.version())).block();

        assertThat(second).isEmpty();
        CatalogEntry current = inTenant(port.findById(DOCTORID)).block();
        assertThat(current.version()).isEqualTo(1);
        assertThat(current.enabled()).isTrue();
    }

    @Test
    void updateIfVersion_ofAnUnknownEntry_isEmpty() {
        assertThat(inTenant(port.updateIfVersion(doctorId(), 0)).block()).isEmpty();
    }

    @Test
    void updateIfVersion_fillsTheSchemaUriWhileItIsNull_andNeverOverwritesIt() {
        CatalogEntry stored = inTenant(port.insert(withUri(doctorId(), null))).block();
        assertThat(stored.schemaUri()).isNull();

        CatalogEntry filled = inTenant(port.updateIfVersion(doctorId(), stored.version())).block().orElseThrow();
        assertThat(filled.schemaUri()).isEqualTo(DOCTORID_URI);

        CatalogEntry other = withUri(doctorId(), "https://registry.eudistack.net/schemas/other/1.0.0/dc+sd-jwt");
        CatalogEntry kept = inTenant(port.updateIfVersion(other, filled.version())).block().orElseThrow();
        assertThat(kept.schemaUri()).isEqualTo(DOCTORID_URI);
    }

    @Test
    void updateIfVersion_ofAnUnfilledRow_returnsItFilled() {
        databaseClient.sql("INSERT INTO \"" + schemaOf(TENANT) + "\".tenant_credential_profile "
                        + "(credential_configuration_id) VALUES ('" + DOCTORID + "')")
                .then().block();
        CatalogEntry unfilled = inTenant(port.findById(DOCTORID)).block();
        assertThat(unfilled.isFilled()).isFalse();
        assertThat(unfilled.deliveryModes()).isNull();
        assertThat(unfilled.validity()).isNull();

        CatalogEntry filled = inTenant(port.updateIfVersion(doctorId(), unfilled.version())).block().orElseThrow();

        assertThat(filled.isFilled()).isTrue();
        assertThat(filled.version()).isEqualTo(unfilled.version() + 1);
    }

    @Test
    void reads_areScopedToTheTenantInTheReactorContext() {
        inTenant(port.insert(doctorId())).block();

        List<CatalogEntry> otherTenant = port.findAll().collectList()
                .contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, "e2e-tenant-b")).block();

        assertThat(otherTenant).extracting(CatalogEntry::credentialConfigurationId).doesNotContain(DOCTORID);
    }

    // ---- helpers ---------------------------------------------------------------

    private static <T> Mono<T> inTenant(Mono<T> mono) {
        return mono.contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private static <T> Flux<T> inTenant(Flux<T> flux) {
        return flux.contextWrite(Context.of(TENANT_DOMAIN_CONTEXT_KEY, TENANT));
    }

    private static CatalogEntry doctorId() {
        return new CatalogEntry(DOCTORID, DOCTORID_URI, true, Set.of(DeliveryMode.EMAIL, DeliveryMode.UI),
                new CatalogEntry.Validity(36500, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("givenName"), ClaimPath.of("familyName")), " "),
                List.of(new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("personal_administrative_number"))),
                0, null, null);
    }

    private static CatalogEntry withId(CatalogEntry entry, String id) {
        return new CatalogEntry(id, entry.schemaUri(), entry.enabled(), entry.deliveryModes(), entry.validity(),
                entry.subject(), entry.searchIdentifiers(), entry.version(), null, null);
    }

    private static CatalogEntry withUri(CatalogEntry entry, String uri) {
        return new CatalogEntry(entry.credentialConfigurationId(), uri, entry.enabled(), entry.deliveryModes(),
                entry.validity(), entry.subject(), entry.searchIdentifiers(), entry.version(), null, null);
    }
}
