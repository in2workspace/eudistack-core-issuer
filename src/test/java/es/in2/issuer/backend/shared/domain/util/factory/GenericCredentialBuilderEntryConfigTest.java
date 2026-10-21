package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialBuildResult;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.CatalogEntryFiller;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.statuslist.domain.util.factory.IssuerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link GenericCredentialBuilder} taking the validity and the subject from the tenant's catalog entry
 * (EUD-266), over the real credential type fixtures in {@code src/test/resources/catalog-profiles}.
 *
 * <p>The subject tests compare the entry-driven subject (list paths resolved against the built
 * credential, D2) with what the type file gives today: both must be the same string for every current
 * type and format.
 */
class GenericCredentialBuilderEntryConfigTest {

    private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();
    private static final String DOCTORID = "doctorid.sd.1";
    private static final String PAST_FROM = "2020-01-01T00:00:00Z";
    private static final String PAST_UNTIL = "2020-12-31T00:00:00Z";

    private final CredentialProfileRegistry registry = new CredentialProfileRegistry(
            OBJECT_MAPPER, new PathMatchingResourcePatternResolver(), "classpath:catalog-profiles");
    private final CatalogEntryFiller filler = new CatalogEntryFiller(registry, new SchemaDeliveryCeiling(registry));
    private final AccessTokenService accessTokenService = mock(AccessTokenService.class);
    private final GenericCredentialBuilder builder =
            new GenericCredentialBuilder(OBJECT_MAPPER, mock(IssuerFactory.class), accessTokenService);

    // --- validity ---

    @Test
    void buildCredential_doctorIdV1_validFor36500DaysIgnoringThePayloadDates() {
        CatalogEntry entry = filler.fill(unfilled(DOCTORID));
        JsonNode payload = doctorPayload().put("validFrom", PAST_FROM).put("validUntil", PAST_UNTIL);

        CredentialBuildResult result = build(DOCTORID, payload, entry);

        assertThat(entry.validity()).isEqualTo(new CatalogEntry.Validity(36500, false, null));
        assertThat(result.validFrom().toInstant()).isCloseTo(Instant.now(), within(1, ChronoUnit.MINUTES));
        assertThat(result.validUntil().toInstant())
                .isCloseTo(Instant.now().plus(36500, ChronoUnit.DAYS), within(1, ChronoUnit.MINUTES));
        assertThat(result.credentialDataSet()).doesNotContain(PAST_FROM, PAST_UNTIL);
    }

    @Test
    void buildCredential_withoutRequesterDates_appliesTheDefaultDays() {
        CatalogEntry entry = configured(new CatalogEntry.Validity(30, true, 60), null);

        CredentialBuildResult result = build(DOCTORID, doctorPayload(), entry);

        assertThat(result.validFrom().toInstant()).isCloseTo(Instant.now(), within(1, ChronoUnit.MINUTES));
        assertThat(result.validUntil().toInstant())
                .isCloseTo(Instant.now().plus(30, ChronoUnit.DAYS), within(1, ChronoUnit.MINUTES));
    }

    @Test
    void buildCredential_requesterDatesNotAllowed_areIgnored() {
        CatalogEntry entry = configured(new CatalogEntry.Validity(30, false, null), null);
        JsonNode payload = doctorPayload().put("validFrom", PAST_FROM).put("validUntil", PAST_UNTIL);

        CredentialBuildResult result = build(DOCTORID, payload, entry);

        assertThat(result.validUntil().toInstant())
                .isCloseTo(Instant.now().plus(30, ChronoUnit.DAYS), within(1, ChronoUnit.MINUTES));
        assertThat(result.credentialDataSet()).doesNotContain(PAST_FROM, PAST_UNTIL);
    }

    /**
     * EUD-254 («today `validFrom` / `validUntil` are ignored and the default validity of the type applies»):
     * {@code requester_can_set_dates} and {@code max_days} are stored but not applied at issuance yet.
     */
    @Test
    void buildCredential_requesterDatesAllowed_areStillIgnored() {
        CatalogEntry entry = configured(new CatalogEntry.Validity(30, true, 60), null);
        Instant from = Instant.now().plus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        Instant until = from.plus(45, ChronoUnit.DAYS);
        JsonNode payload = doctorPayload().put("validFrom", from.toString()).put("validUntil", until.toString());

        CredentialBuildResult result = build(DOCTORID, payload, entry);

        assertThat(result.validFrom().toInstant()).isCloseTo(Instant.now(), within(1, ChronoUnit.MINUTES));
        assertThat(result.validUntil().toInstant())
                .isCloseTo(Instant.now().plus(30, ChronoUnit.DAYS), within(1, ChronoUnit.MINUTES));
        assertThat(result.credentialDataSet()).doesNotContain(from.toString(), until.toString());
    }

    @Test
    void buildCredential_unfilledEntry_usesTheValidityOfTheTypeFile() {
        CatalogEntry unfilled = unfilled(DOCTORID);
        JsonNode payload = doctorPayload().put("validFrom", PAST_FROM).put("validUntil", PAST_UNTIL);

        CredentialBuildResult result = build(DOCTORID, payload, unfilled);

        assertThat(unfilled.isFilled()).isFalse();
        assertThat(result.validUntil().toInstant())
                .isCloseTo(Instant.now().plus(36500, ChronoUnit.DAYS), within(1, ChronoUnit.MINUTES));
    }

    // --- subject ---

    @Test
    void buildCredential_subjectJoinedWithTheEntrySeparator() {
        CatalogEntry entry = configured(new CatalogEntry.Validity(30, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("givenName"), ClaimPath.of("familyName")), "-"));

        assertThat(build(DOCTORID, doctorPayload(), entry).subject()).isEqualTo("Jane-Doe");
    }

    @Test
    void buildCredential_subjectWithoutSeparator_isJoinedWithASpace() {
        CatalogEntry entry = configured(new CatalogEntry.Validity(30, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("familyName"), ClaimPath.of("givenName")), null));

        assertThat(build(DOCTORID, doctorPayload(), entry).subject()).isEqualTo("Doe Jane");
    }

    @Test
    void buildCredential_subjectSkipsFieldsWithoutValue() {
        CatalogEntry entry = configured(new CatalogEntry.Validity(30, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("givenName"), ClaimPath.of("medical_speciality"),
                        ClaimPath.of("familyName")), " "));

        assertThat(build(DOCTORID, doctorPayload(), entry).subject()).isEqualTo("Jane Doe");
    }

    @Test
    void buildCredential_entryWithoutSubject_hasAnEmptySubject() {
        CatalogEntry entry = configured(new CatalogEntry.Validity(30, false, null), null);

        assertThat(build(DOCTORID, doctorPayload(), entry).subject()).isEmpty();
    }

    @Test
    void buildCredential_entryWithoutSubject_doesNotGoBackToTheTypeFile() {
        // The type file declares a subject (givenName familyName), the entry deliberately has none (D9).
        assertThat(build(DOCTORID, doctorPayload(), unfilled(DOCTORID)).subject()).isEqualTo("Jane Doe");
        assertThat(build(DOCTORID, doctorPayload(), configured(new CatalogEntry.Validity(30, false, null), null))
                .subject()).isEmpty();
    }

    @Test
    void buildCredential_leafInsideARepeatedObject_isNotASubject() {
        CatalogEntry entry = configured(new CatalogEntry.Validity(30, false, null),
                new CatalogEntry.Subject(List.of(ClaimPath.of("givenName", "missing")), " "));

        assertThat(build(DOCTORID, doctorPayload(), entry).subject()).isEmpty();
    }

    /** D2 must not change the subject of any current type: same string through the entry and through the file. */
    @ParameterizedTest
    @ValueSource(strings = {"learcredential.employee.sd.1", "learcredential.employee.w3c.4"})
    void buildCredential_learMandate_givesTheSameSubjectAsTheTypeFile(String ccid) {
        JsonNode payload = learPayload();

        String fromTypeFile = build(ccid, payload, null).subject();
        String fromEntry = build(ccid, payload, filler.fill(unfilled(ccid))).subject();

        assertThat(fromTypeFile).isEqualTo("John Doe");
        assertThat(fromEntry).isEqualTo(fromTypeFile);
    }

    @Test
    void buildCredential_gaiaXLabel_appliesTheLastSegmentDelimiterOfTheTypeFile() {
        when(accessTokenService.getOrganizationIdFromCurrentSession()).thenReturn(Mono.just("ORG"));
        JsonNode payload = OBJECT_MAPPER.createObjectNode().set("credentialSubject",
                OBJECT_MAPPER.createObjectNode().put("id", "did:elsi:VATES-B12345678"));

        String fromTypeFile = build("gx.labelcredential.w3c.2", payload, null).subject();
        String fromEntry = build("gx.labelcredential.w3c.2", payload,
                filler.fill(unfilled("gx.labelcredential.w3c.2"))).subject();

        assertThat(fromTypeFile).isEqualTo("VATES-B12345678");
        assertThat(fromEntry).isEqualTo(fromTypeFile);
    }

    // --- helpers ---

    private CredentialBuildResult build(String ccid, JsonNode payload, CatalogEntry entry) {
        CredentialProfile profile = registry.getByConfigurationId(ccid);
        CredentialBuildResult result = builder.buildCredential(profile, payload, entry).block();
        assertThat(result).isNotNull();
        return result;
    }

    private static com.fasterxml.jackson.databind.node.ObjectNode doctorPayload() {
        return OBJECT_MAPPER.createObjectNode().put("givenName", "Jane").put("familyName", "Doe");
    }

    private static JsonNode learPayload() {
        var payload = OBJECT_MAPPER.createObjectNode();
        payload.putObject("mandator").put("organizationIdentifier", "VATES-B12345678");
        payload.putObject("mandatee").put("firstName", "John").put("lastName", "Doe");
        return payload;
    }

    private static CatalogEntry unfilled(String ccid) {
        return new CatalogEntry(ccid, null, true, null, null, null, List.of(), 0, null, null);
    }

    private static CatalogEntry configured(CatalogEntry.Validity validity, CatalogEntry.Subject subject) {
        return new CatalogEntry(DOCTORID, null, true, Set.of(DeliveryMode.EMAIL), validity, subject, List.of(), 1,
                null, null);
    }
}
