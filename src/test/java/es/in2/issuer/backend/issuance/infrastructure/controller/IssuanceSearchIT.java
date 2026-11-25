package es.in2.issuer.backend.issuance.infrastructure.controller;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import es.in2.issuer.backend.shared.domain.exception.TenantSecretKeyUnavailableException;
import es.in2.issuer.backend.shared.domain.model.catalog.CatalogEntry;
import es.in2.issuer.backend.shared.domain.model.catalog.ClaimPath;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.searchidentifier.SearchIdentifierFingerprinter;
import es.in2.issuer.backend.shared.domain.service.SearchIdentifierIndexer;
import es.in2.issuer.backend.shared.domain.spi.CatalogEntryPort;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.shared.domain.spi.TenantSecretKeyPort;
import es.in2.issuer.backend.shared.domain.util.SubjectSearch;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-255 FR-05 and FR-11 over real HTTP and Postgres (AC-05, AC-06, AC-07, EC-05, EC-06, AC-12, ES-02):
 * {@code POST /api/v1/issuances/search} by name finds the processes of the caller's scope whose subject contains the
 * text, ignoring case and accents; by identifier, those whose fingerprint with the tenant key is the one of the value
 * searched. Both with the pages of the listing, and with a strict trace holding the value searched -- the one place
 * it is kept.
 */
@TestPropertySource(properties = {
        "auditoria.publisher.enabled=true",
        "auditoria.dispatcher.enabled=false",
        "logging.level.es.in2=DEBUG"})
class IssuanceSearchIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-a";
    private static final String OTHER_TENANT = "e2e-tenant-b";
    private static final Instant T = Instant.parse("2026-10-01T09:00:00Z");

    /** Every observation that finished, as text: name, key values and context. */
    static final class Observations implements ObservationHandler<Observation.Context> {

        private final List<String> finished = new CopyOnWriteArrayList<>();

        @Override
        public boolean supportsContext(Observation.Context context) {
            return true;
        }

        @Override
        public void onStop(Observation.Context context) {
            finished.add(context.getName() + " " + context.getContextualName() + " "
                    + context.getLowCardinalityKeyValues() + " " + context.getHighCardinalityKeyValues() + " " + context);
        }

        List<String> finished() {
            return List.copyOf(finished);
        }

        void clear() {
            finished.clear();
        }
    }

    /**
     * The tenant keys of these tests (outside the local profile there is no Parameter Store): one per tenant, which
     * a test can make unreadable (ES-02).
     */
    static final class TestTenantKeys implements TenantSecretKeyPort {

        private final AtomicBoolean readable = new AtomicBoolean(true);

        @Override
        public Mono<byte[]> keyOf(String tenant) {
            return readable.get()
                    ? Mono.just(Arrays.copyOf(("it-search-key-" + tenant).getBytes(StandardCharsets.UTF_8), 32))
                    : Mono.error(new TenantSecretKeyUnavailableException("The test made the key unreadable"));
        }

        void unreadable() {
            readable.set(false);
        }

        void readable() {
            readable.set(true);
        }
    }

    @TestConfiguration
    static class ObservationRecording {

        @Bean
        Observations allObservations() {
            return new Observations();
        }

        @Bean
        @Primary
        TestTenantKeys testTenantKeys() {
            return new TestTenantKeys();
        }
    }

    @Autowired
    private IssuancePort issuancePort;

    @Autowired
    private Observations observations;

    @Autowired
    private TestTenantKeys tenantKeys;

    @Autowired
    private CatalogEntryPort catalogEntryPort;

    @Autowired
    private SearchIdentifierIndexer searchIdentifierIndexer;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();

    @BeforeEach
    void captureLogs() {
        Logger root = ((LoggerContext) LoggerFactory.getILoggerFactory()).getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        logs.start();
        root.addAppender(logs);
        observations.clear();
    }

    @AfterEach
    void releaseLogs() {
        Logger root = ((LoggerContext) LoggerFactory.getILoggerFactory()).getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        root.detachAppender(logs);
        logs.stop();
        tenantKeys.readable();
    }

    // ---- search by identifier (EUD-270 task 6) ---------------------------------------------------------------

    /** AC-05, EC-06: the process with that identifier, however it is written, within the caller's scope. */
    @Test
    void byIdentifier_findsTheProcessWithIt_howeverTheValueIsWritten() {
        String organization = uniqueOrganization();
        String entry = colegiadoEntry();
        String value = uniqueColegiado();
        Issuance withIt = seedWithAttestation(TENANT, organization, entry, colegiado(value), T.plusSeconds(1));
        seedWithAttestation(TENANT, organization, entry, "{\"credentialSubject\":{\"name\":\"Ana\"}}", T.plusSeconds(2));
        seedWithAttestation(TENANT, uniqueOrganization(), entry, colegiado(value), T.plusSeconds(3));

        assertThat(ids(search(organization, byColegiado(value, "\"life_cycle_status\": [\"VALID\"]"))))
                .containsExactly(id(withIt));
        assertThat(ids(search(organization, byColegiado(" " + value.replace("/", " / ").toLowerCase() + " ", null))))
                .containsExactly(id(withIt));
    }

    /** AC-06: no process with it is an empty page; a type no entry declares, unknown_identifier_type, traced. */
    @Test
    void byIdentifier_withoutMatches_isAnEmptyPage_andOfAnUnknownType_isUnknownIdentifierType() {
        String organization = uniqueOrganization();
        colegiadoEntry();
        String unknownType = "unknown" + UUID.randomUUID().toString().substring(0, 8);
        String value = uniqueColegiado();

        Map<String, Object> empty = search(organization, byColegiado(value, null));
        Map<String, Object> unknown = webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, organization))
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"identifier_type\": \"" + unknownType + "\", \"identifier\": \"" + value + "\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult().getResponseBody();

        assertThat(issuances(empty)).isEmpty();
        assertThat(empty).containsEntry("next_cursor", null);
        assertThat(unknown).containsEntry("type", "unknown_identifier_type");
        assertThat(unknown.toString()).doesNotContain(value);
        Map<String, Object> trace = databaseClient.sql("SELECT payload->>'result' AS result, payload->>'reason' AS reason "
                        + "FROM public.audit_outbox WHERE event_type = 'IssuanceQueried' "
                        + "AND payload->'details'->'filters'->>'identifier_type' = :type")
                .bind("type", unknownType)
                .fetch().one().block(Duration.ofSeconds(10));
        assertThat(trace).containsEntry("result", "Denied").containsEntry("reason", "UnknownIdentifierType");
    }

    /** AC-12: from the platform tenant, the search by identifier names its tenant and searches only there. */
    @Test
    void fromThePlatformTenant_theSearchByIdentifier_needsTheTenant_andSearchesThere() {
        String entry = colegiadoEntry();
        String value = uniqueColegiado();
        Issuance inA = seedWithAttestation(TENANT, uniqueOrganization(), entry, colegiado(value), T);

        Map<String, Object> withoutTenant = platformSearch(byColegiado(value, null), HttpStatus.BAD_REQUEST);
        Map<String, Object> inTenant = platformSearch(byColegiado(value, "\"tenant\": \"" + TENANT + "\""), HttpStatus.OK);

        assertThat(fields(withoutTenant)).containsExactly("tenant");
        assertThat(issuances(inTenant)).extracting(issuance -> issuance.get("id"), issuance -> issuance.get("tenant"))
                .containsExactly(org.assertj.core.groups.Tuple.tuple(id(inA), TENANT));
    }

    /** ES-02: without the tenant key the search by identifier is internal_error; the search by name goes on. */
    @Test
    void withoutTheTenantKey_theSearchByIdentifierIsAnInternalError_andTheSearchByNameGoesOn() {
        String organization = uniqueOrganization();
        colegiadoEntry();
        tenantKeys.unreadable();

        webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, organization))
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(byColegiado(uniqueColegiado(), null))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR)
                .expectBody().jsonPath("$.type").isEqualTo("internal_error")
                .jsonPath("$.issuances").doesNotExist();
        assertThat(search(organization, "{\"subject\": \"garcia\"}")).containsKey("issuances");
    }

    /** AD-7: the trace keeps the identifier as it was sent, with its type and the count. */
    @Test
    void theSearchByIdentifier_isTraced_withTheValueAsSent() {
        String organization = uniqueOrganization();
        String entry = colegiadoEntry();
        String value = uniqueColegiado();
        seedWithAttestation(TENANT, organization, entry, colegiado(value), T);
        String sent = value.replace("/", " / ");

        search(organization, byColegiado(sent, null));

        Map<String, Object> trace = databaseClient.sql("SELECT payload->>'result' AS result, "
                        + "payload->'details'->'filters'->>'identifier_type' AS type, "
                        + "payload->'details'->>'returned_count' AS returned_count FROM public.audit_outbox "
                        + "WHERE event_type = 'IssuanceQueried' AND payload->'details'->'filters'->>'identifier' = :sent")
                .bind("sent", sent)
                .fetch().one().block(Duration.ofSeconds(10));
        assertThat(trace).containsEntry("result", "Success")
                .containsEntry("type", "colegiado")
                .containsEntry("returned_count", "1");
    }

    /**
     * AC-09 and NFR-2 for the identifier: a search that finds a process, and one refused for its shape, with a value
     * written as nowhere else; then it is looked for as sent and as fingerprinted in the logs, the observations and
     * every text column. As sent, it may only be in {@code public.audit_outbox}, once; what the search leaves
     * besides is its fingerprint, which is not text.
     */
    @Test
    void theIdentifierSearched_isOnlyInTheAuditTrail() {
        // Given: a process with the identifier, which the search writes otherwise
        String entry = colegiadoEntry();
        String marker = "QX" + UUID.randomUUID().toString().replace("-", "").substring(0, 10).toUpperCase();
        String stored = "28/" + marker;
        String sent = "28 / " + marker.toLowerCase();
        String organization = "VATES-LEAK-" + UUID.randomUUID();
        seedWithAttestation(TENANT, organization, entry, colegiado(stored), T);
        Map<String, Long> before = occurrencesInTables(sent);
        String token = mintOperatorAccessToken(TENANT, organization);
        logs.list.clear();
        observations.clear();

        // When: a search that finds it and one refused for its shape
        webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(byColegiado(sent, null))
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.issuances.length()").isEqualTo(1);
        webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"identifier\": \"" + sent + "\"}")
                .exchange()
                .expectStatus().isBadRequest();

        // Then: the capture works -- the requests did log and observe something
        assertThat(logs.list).isNotEmpty();
        assertThat(observations.finished()).anySatisfy(observation -> assertThat(observation).contains("/api/v1/issuances/search"));
        // ...and neither the value as sent nor as fingerprinted is in a log or an observation
        for (String value : List.of(sent, SearchIdentifierFingerprinter.normalize(sent), marker)) {
            assertThat(logLines()).as("logs").noneSatisfy(line -> assertThat(line).containsIgnoringCase(value));
            assertThat(observations.finished()).as("observations").noneSatisfy(line -> assertThat(line).containsIgnoringCase(value));
        }
        // ...nor in a table, but in the audit trail of the search that was made
        assertThat(occurrencesInTables(sent)).as("text columns holding the value searched").isEqualTo(before);
        assertThat(databaseClient.sql("SELECT count(*) AS n FROM public.audit_outbox WHERE payload::text LIKE :sent")
                .bind("sent", "%" + sent + "%")
                .fetch().one().block(Duration.ofSeconds(10))).containsEntry("n", 1L);
    }

    private Map<String, Object> platformSearch(String body, HttpStatus expected) {
        return webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + platformAdministratorToken())
                .header(X_TENANT_HEADER, "platform")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isEqualTo(expected)
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult().getResponseBody();
    }

    /** A catalogue entry of the tenant that declares colegiado; disabled, so it serves no issuance of other tests. */
    private String colegiadoEntry() {
        String id = "eud270." + UUID.randomUUID().toString().substring(0, 8);
        catalogEntryPort.insert(new CatalogEntry(id, null, false, null, null, null,
                        List.of(new CatalogEntry.SearchIdentifier("colegiado", ClaimPath.of("credentialSubject", "colegiado"))),
                        0, null, null))
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
        return id;
    }

    /** Through the creation of the issuance, which writes the fingerprints with the process. */
    private Issuance seedWithAttestation(String tenant, String organization, String entry, String attestation,
                                         Instant lastChangedAt) {
        Issuance issuance = Issuance.builder()
                .credentialFormat("dc+sd-jwt")
                .credentialDataSet(attestation)
                .credentialStatus(CredentialStatusEnum.VALID)
                .organizationIdentifier(organization)
                .credentialType(entry)
                .subject("Holder " + UUID.randomUUID())
                .email("holder@example.com")
                .delivery("email")
                .lastChangedAt(lastChangedAt.truncatedTo(ChronoUnit.MICROS))
                .build();
        return searchIdentifierIndexer.saveWithFingerprints(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .block();
    }

    private static String colegiado(String value) {
        return "{\"credentialSubject\":{\"colegiado\":\"" + value + "\"}}";
    }

    private static String byColegiado(String value, String moreFields) {
        return "{\"identifier_type\": \"colegiado\", \"identifier\": \"" + value + "\""
                + (moreFields == null ? "" : ", " + moreFields) + "}";
    }

    private static String uniqueColegiado() {
        return "28/" + UUID.randomUUID().toString().replace("-", "").substring(0, 10).toUpperCase();
    }


    /** AC-07 and EC-05: partial, without case nor accents, and only the processes whose subject has it. */
    @Test
    void byName_ignoresCaseAndAccents_andFindsOnlyThoseThatContainIt() {
        String organization = uniqueOrganization();
        Issuance garcia = seed(TENANT, organization, "María García López", T.plusSeconds(2));
        seed(TENANT, organization, "Mario Garcés", T.plusSeconds(1));
        seed(TENANT, uniqueOrganization(), "María García López", T.plusSeconds(3));

        assertThat(ids(search(organization, "{\"subject\": \"garcia\"}"))).containsExactly(id(garcia));
        assertThat(ids(search(organization, "{\"subject\": \"GARCÍA\"}"))).containsExactly(id(garcia));
        assertThat(ids(search(organization, "{\"subject\": \"  GARCÍA   lóp\"}"))).containsExactly(id(garcia));
        assertThat(ids(search(organization, "{\"subject\": \"garc\"}"))).hasSize(2);
    }

    /** The wildcards of LIKE in the text are matched as themselves, never as patterns. */
    @Test
    void theWildcardsOfLike_areSearchedLiterally() {
        String organization = uniqueOrganization();
        seed(TENANT, organization, "Ana Pérez", T);

        assertThat(ids(search(organization, "{\"subject\": \"%%%\"}"))).isEmpty();
        assertThat(ids(search(organization, "{\"subject\": \"___\"}"))).isEmpty();
    }

    @Test
    void thePages_ofASearch_walkItsResultsOnce_andTheCursorServesOnlyThatText() {
        String organization = uniqueOrganization();
        Issuance newer = seed(TENANT, organization, "Lucía Fernández", T.plusSeconds(2));
        Issuance older = seed(TENANT, organization, "Lucas Fernández", T.plusSeconds(1));
        seed(TENANT, organization, "Pedro Ruiz", T.plusSeconds(3));

        Map<String, Object> first = search(organization, "{\"subject\": \"fernandez\", \"limit\": 1}");
        String cursor = (String) first.get("next_cursor");
        Map<String, Object> second = search(organization,
                "{\"subject\": \"FERNÁNDEZ\", \"limit\": 1, \"cursor\": \"" + cursor + "\"}");

        assertThat(ids(first)).containsExactly(id(newer));
        assertThat(ids(second)).containsExactly(id(older));
        assertThat(second).containsEntry("next_cursor", null);
        assertThat(fields(problem(organization, "{\"subject\": \"ruiz\", \"limit\": 1, \"cursor\": \"" + cursor + "\"}")))
                .containsExactly("cursor");
    }

    /** AC-07, EC-05, ES-04: the shape is refused with the field named and never the value. */
    @Test
    void aMalformedSearch_isAnInvalidRequest_namingTheFieldWithoutTheValue() {
        String organization = uniqueOrganization();

        Map<String, Object> tooShort = problem(organization, "{\"subject\": \"g a\"}");
        Map<String, Object> both = problem(organization, "{\"subject\": \"garcia\", \"identifier_type\": \"dni\", \"identifier\": \"12345678Z\"}");
        Map<String, Object> notJson = problem(organization, "{\"subject\": Garcia");

        assertThat(tooShort).containsEntry("type", "invalid_request");
        assertThat(fields(tooShort)).containsExactly("subject");
        assertThat(fields(both)).containsExactly("subject");
        assertThat(fields(notJson)).containsExactly("body");
        assertThat(both.toString()).doesNotContain("12345678Z").doesNotContain("garcia");
        assertThat(notJson.toString()).doesNotContain("Garcia");
    }

    /** AC-12: an administrator of a tenant may not name a tenant in the search. */
    @Test
    void theTenantField_outsideThePlatformTenant_isAnInvalidRequest() {
        assertThat(fields(problem(uniqueOrganization(), "{\"subject\": \"garcia\", \"tenant\": \"sandbox\"}")))
                .containsExactly("tenant");
    }

    /** AC-12: from the platform tenant, the search by name crosses every tenant and says which one. */
    @Test
    void fromThePlatformTenant_theSearchByName_crossesEveryTenant() {
        String surname = "Quintanilla" + UUID.randomUUID().toString().substring(0, 8);
        Issuance inA = seed(TENANT, uniqueOrganization(), "Elena " + surname, T.plusSeconds(1));
        Issuance inB = seed(OTHER_TENANT, uniqueOrganization(), "Elena " + surname, T.plusSeconds(2));

        Map<String, Object> page = webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + platformAdministratorToken())
                .header(X_TENANT_HEADER, "platform")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subject\": \"" + surname.toUpperCase() + "\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult().getResponseBody();

        assertThat(issuances(page)).extracting(issuance -> issuance.get("id"), issuance -> issuance.get("tenant"))
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(id(inB), OTHER_TENANT),
                        org.assertj.core.groups.Tuple.tuple(id(inA), TENANT));
    }

    /** AC-09 for the name: the trace keeps the text as it was sent, with the other filters and the count. */
    @Test
    void theSearch_isTraced_withTheTextAsSent_andTheNumberReturned() {
        String organization = uniqueOrganization();
        String text = "Bénédicte" + UUID.randomUUID().toString().substring(0, 6);
        seed(TENANT, organization, text + " Dupont", T);

        search(organization, "{\"subject\": \"" + text + "\", \"life_cycle_status\": [\"VALID\"]}");

        Map<String, Object> trace = databaseClient.sql("SELECT payload->>'result' AS result, "
                        + "payload->'details'->'filters'->>'subject' AS subject, "
                        + "payload->'details'->'filters'->'life_cycle_status'->>0 AS status, "
                        + "payload->'details'->>'returned_count' AS returned_count FROM public.audit_outbox "
                        + "WHERE event_type = 'IssuanceQueried' AND payload->'details'->'filters'->>'subject' = :text")
                .bind("text", text)
                .fetch().one().block(Duration.ofSeconds(10));
        assertThat(trace).containsEntry("result", "Success")
                .containsEntry("subject", text)
                .containsEntry("status", "VALID")
                .containsEntry("returned_count", "1");
    }

    /**
     * AC-09 and NFR-2 for the name: a search, a valid one and one refused for its shape, with a text that exists
     * nowhere else; then it is looked for in the address, the logs (what the OpenTelemetry appender exports), every
     * observation (what becomes a span) and every text column of the tenant's schema and of {@code public}. It may
     * only be in {@code public.audit_outbox}, once per search. The search by identifier has the same proof in
     * {@link #theIdentifierSearched_isOnlyInTheAuditTrail}.
     */
    @Test
    void theTextSearched_isOnlyInTheAuditTrail() {
        // Given: a process whose subject matches the text only once normalized, so the text as sent exists nowhere
        String marker = "zqx" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        String sent = "Ñ" + marker.toUpperCase() + "É";
        String organization = "VATES-LEAK-" + UUID.randomUUID();
        seed(TENANT, organization, "Ana N" + marker + "e Prado", T);
        Map<String, Long> before = occurrencesInTables(sent);
        String token = mintOperatorAccessToken(TENANT, organization);
        logs.list.clear();
        observations.clear();

        // When: a search that finds it and one refused for its shape
        webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subject\": \"" + sent + "\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.issuances.length()").isEqualTo(1);
        webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subject\": \"" + sent + "\", \"identifier\": \"" + sent + "\"}")
                .exchange()
                .expectStatus().isBadRequest();

        // Then: the capture works -- the requests did log and observe something
        assertThat(logs.list).isNotEmpty();
        assertThat(observations.finished()).anySatisfy(observation -> assertThat(observation).contains("/api/v1/issuances/search"));
        // ...and neither the text as sent nor its compared form is in a log, an observation or an address
        String compared = SubjectSearch.normalize(sent);
        for (String value : List.of(sent, compared, marker.toUpperCase())) {
            assertThat(logLines()).as("logs").noneSatisfy(line -> assertThat(line).containsIgnoringCase(value));
            assertThat(observations.finished()).as("observations").noneSatisfy(line -> assertThat(line).contains(value));
        }
        // ...nor in a table, but in the audit trail of the search that was made
        Map<String, Long> after = occurrencesInTables(sent);
        assertThat(after).as("text columns holding the text searched").isEqualTo(before);
        assertThat(databaseClient.sql("SELECT count(*) AS n FROM public.audit_outbox WHERE payload::text LIKE :text")
                .bind("text", "%" + sent + "%")
                .fetch().one().block(Duration.ofSeconds(10))).containsEntry("n", 1L);
    }

    /** Every log event as text: the message with its arguments, and the messages of its exceptions. */
    private List<String> logLines() {
        List<String> lines = new ArrayList<>();
        for (ILoggingEvent event : List.copyOf(logs.list)) {
            StringBuilder line = new StringBuilder(event.getLoggerName()).append(' ').append(event.getFormattedMessage());
            event.getMDCPropertyMap().forEach((key, value) -> line.append(' ').append(key).append('=').append(value));
            for (IThrowableProxy error = event.getThrowableProxy(); error != null; error = error.getCause()) {
                line.append(' ').append(error.getClassName()).append(": ").append(error.getMessage());
            }
            lines.add(line.toString());
        }
        return lines;
    }

    /**
     * How many rows of each text column of the tenant's schema and of {@code public} contain the text, but for the
     * audit outbox, which is where it must be.
     */
    private Map<String, Long> occurrencesInTables(String text) {
        List<Map<String, Object>> columns = databaseClient.sql("SELECT table_schema, table_name, column_name "
                        + "FROM information_schema.columns c "
                        + "JOIN information_schema.tables t USING (table_schema, table_name) "
                        + "WHERE t.table_type = 'BASE TABLE' AND table_schema IN (:schemas) "
                        + "AND data_type IN ('text', 'character varying', 'character', 'json', 'jsonb') "
                        + "AND NOT (table_schema = 'public' AND table_name = 'audit_outbox') "
                        + "ORDER BY 1, 2, 3")
                .bind("schemas", List.of(TENANT + SCHEMA_SUFFIX, "public"))
                .fetch().all().collectList().block(Duration.ofSeconds(10));
        assertThat(columns).as("the tenant's tables are scanned").isNotEmpty();
        Map<String, Long> occurrences = new LinkedHashMap<>();
        for (Map<String, Object> column : columns) {
            String qualified = quoted(column.get("table_schema")) + "." + quoted(column.get("table_name"));
            String name = quoted(column.get("column_name"));
            Map<String, Object> count = databaseClient.sql("SELECT count(*) AS n FROM " + qualified
                            + " WHERE " + name + "::text ILIKE :text")
                    .bind("text", "%" + text + "%")
                    .fetch().one().block(Duration.ofSeconds(10));
            occurrences.put(qualified + "." + name, ((Number) count.get("n")).longValue());
        }
        return occurrences;
    }

    private static String quoted(Object identifier) {
        return "\"" + identifier.toString().replace("\"", "\"\"") + "\"";
    }

    private Map<String, Object> search(String organization, String body) {
        return webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, organization))
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isOk()
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult().getResponseBody();
    }

    private Map<String, Object> problem(String organization, String body) {
        return webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, organization))
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.BAD_REQUEST)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult().getResponseBody();
    }

    private String platformAdministratorToken() {
        return mintUserAccessToken("platform", "VATES-PLATFORM-ADMIN", List.of(Map.of(
                        "type", "organization", "domain", "EUDISTACK", "function", "System", "action", List.of("Administration"))),
                "platform.admin@example.com");
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> issuances(Map<String, Object> page) {
        return (List<Map<String, Object>>) page.get("issuances");
    }

    private static List<Object> ids(Map<String, Object> page) {
        return issuances(page).stream().map(issuance -> issuance.get("id")).toList();
    }

    @SuppressWarnings("unchecked")
    private static List<String> fields(Map<String, Object> problem) {
        return ((List<Map<String, Object>>) problem.get("violations")).stream()
                .map(violation -> (String) violation.get("field"))
                .toList();
    }

    private static String id(Issuance issuance) {
        return issuance.getIssuanceId().toString();
    }

    private Issuance seed(String tenant, String organization, String subject, Instant lastChangedAt) {
        Issuance issuance = Issuance.builder()
                .credentialFormat("dc+sd-jwt")
                .credentialDataSet("{}")
                .credentialStatus(CredentialStatusEnum.VALID)
                .organizationIdentifier(organization)
                .credentialType("doctor.sd.1")
                .subject(subject)
                .email("holder@example.com")
                .delivery("email")
                .lastChangedAt(lastChangedAt.truncatedTo(ChronoUnit.MICROS))
                .build();
        return issuancePort.insert(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .block();
    }

    private static String uniqueOrganization() {
        return "VATES-SEARCH-" + UUID.randomUUID();
    }
}
