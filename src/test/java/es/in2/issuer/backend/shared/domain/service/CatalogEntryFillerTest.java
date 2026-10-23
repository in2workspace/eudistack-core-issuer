package es.in2.issuer.backend.shared.domain.service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link CatalogEntryFiller} over the real credential type fixtures in
 * {@code src/test/resources/catalog-profiles}: what a row seeded with only its
 * {@code credential_configuration_id} becomes.
 */
class CatalogEntryFillerTest {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    private final CredentialProfileRegistry registry = new CredentialProfileRegistry(
            OBJECT_MAPPER, new PathMatchingResourcePatternResolver(), "classpath:catalog-profiles");
    private final CatalogEntryFiller filler = new CatalogEntryFiller(registry, new SchemaDeliveryCeiling(registry));

    @Test
    void fill_ofDoctorIdV1_takesItsValiditySubjectSchemaUriAndCeiling() {
        CatalogEntry filled = filler.fill(unfilled("doctorid.sd.1"));

        assertThat(filled.schemaUri()).isEqualTo("https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt");
        assertThat(filled.validity()).isEqualTo(new CatalogEntry.Validity(36500, false, null));
        assertThat(filled.subject()).isEqualTo(new CatalogEntry.Subject(
                List.of(ClaimPath.of("givenName"), ClaimPath.of("familyName")), " "));
        assertThat(filled.deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.EMAIL, DeliveryMode.UI);
        assertThat(filled.searchIdentifiers()).isEmpty();
    }

    @Test
    void fill_ofLearSdJwt_prefixesTheSubjectPathsWithMandate() {
        CatalogEntry filled = filler.fill(unfilled("learcredential.employee.sd.1"));

        assertThat(filled.subject().fields()).containsExactly(
                ClaimPath.of("mandate", "mandatee", "firstName"), ClaimPath.of("mandate", "mandatee", "lastName"));
        assertThat(filled.validity()).isEqualTo(new CatalogEntry.Validity(365, false, null));
    }

    @Test
    void fill_ofLearW3c_prefixesTheSubjectPathsWithCredentialSubjectAndMandate() {
        CatalogEntry filled = filler.fill(unfilled("learcredential.employee.w3c.4"));

        assertThat(filled.subject().fields()).containsExactly(
                ClaimPath.of("credentialSubject", "mandate", "mandatee", "firstName"),
                ClaimPath.of("credentialSubject", "mandate", "mandatee", "lastName"));
    }

    @Test
    void fill_ofGaiaXLabel_keepsTheDirectPathAndAllowsEveryDeliveryMode() {
        CatalogEntry filled = filler.fill(unfilled("gx.labelcredential.w3c.2"));

        assertThat(filled.subject().fields()).containsExactly(ClaimPath.of("credentialSubject", "id"));
        assertThat(filled.deliveryModes()).containsExactlyInAnyOrder(DeliveryMode.values());
    }

    @Test
    void fill_takesTheValidityDaysOfTheTypeFile_withoutRequesterDates() {
        CatalogEntry filled = filler.fill(unfilled("learcredential.employee.sd.1"));

        assertThat(filled.validity()).isEqualTo(new CatalogEntry.Validity(365, false, null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"doctorid.sd.1", "learcredential.employee.sd.1", "learcredential.employee.w3c.4",
            "gx.labelcredential.w3c.2"})
    void fill_producesSubjectPathsThatAreAllAttributesOfTheSchema(String ccid) {
        CatalogEntry filled = filler.fill(unfilled(ccid));

        assertThat(filled.subject().fields()).isNotEmpty()
                .allSatisfy(path -> assertThat(registry.attributePaths(ccid)).contains(path));
    }

    @Test
    void fill_ofATypeWithoutSchemaUri_leavesItNull() {
        assertThat(filler.fill(unfilled("learcredential.employee.sd.1")).schemaUri()).isNull();
    }

    @Test
    void fill_ofARowWithoutSchemaUri_keepsAnAlreadyStoredOne() {
        CatalogEntry stored = with(unfilled("doctorid.sd.1"), "https://registry.eudistack.net/schemas/other", null);

        assertThat(filler.fill(stored).schemaUri()).isEqualTo("https://registry.eudistack.net/schemas/other");
    }

    @Test
    void fill_keepsTheStoredDeliveryModes_andOnlyMaterialisesNull() {
        CatalogEntry stored = with(unfilled("doctorid.sd.1"), null, Set.of(DeliveryMode.UI));

        assertThat(filler.fill(stored).deliveryModes()).containsExactly(DeliveryMode.UI);
    }

    @Test
    void fill_keepsAnExplicitEmptyListOfModes() {
        CatalogEntry disabled = new CatalogEntry("doctorid.sd.1", null, false, Set.of(), null, null,
                List.of(), 3, null, null);

        assertThat(filler.fill(disabled).deliveryModes()).isEmpty();
    }

    @Test
    void fill_ofAConfiguredEntryWithoutSubject_doesNotGoBackToTheFile() {
        CatalogEntry configured = new CatalogEntry("doctorid.sd.1", null, true, Set.of(DeliveryMode.EMAIL),
                new CatalogEntry.Validity(30, false, null), null, List.of(), 2, null, null);

        CatalogEntry filled = filler.fill(configured);

        assertThat(filled.subject()).isNull();
        assertThat(filled.validity()).isEqualTo(new CatalogEntry.Validity(30, false, null));
    }

    @Test
    void fill_isIdempotentAndKeepsVersionAndTimestamps() {
        Instant created = Instant.parse("2026-01-01T00:00:00Z");
        CatalogEntry seeded = new CatalogEntry("doctorid.sd.1", null, true, null, null, null, List.of(), 4,
                created, created);

        CatalogEntry once = filler.fill(seeded);
        CatalogEntry twice = filler.fill(once);

        assertThat(twice).isEqualTo(once).isNotEqualTo(seeded);
        assertThat(once.isFilled()).isTrue();
        assertThat(once.version()).isEqualTo(4);
        assertThat(once.created()).isEqualTo(created);
    }

    @Test
    void fill_ofATypeWhoseFileIsNotLoaded_returnsTheEntryUnchanged() {
        CatalogEntry orphan = unfilled("removed.type.1");

        assertThat(filler.fill(orphan)).isSameAs(orphan);
    }

    private static CatalogEntry unfilled(String ccid) {
        return new CatalogEntry(ccid, null, true, null, null, null, List.of(), 0, null, null);
    }

    private static CatalogEntry with(CatalogEntry entry, String schemaUri, Set<DeliveryMode> modes) {
        return new CatalogEntry(entry.credentialConfigurationId(), schemaUri, entry.enabled(), modes,
                entry.validity(), entry.subject(), entry.searchIdentifiers(), entry.version(), null, null);
    }
}
