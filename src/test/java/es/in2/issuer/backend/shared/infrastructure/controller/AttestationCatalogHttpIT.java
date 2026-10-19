package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Attestation Catalogue API over real HTTP (server under {@code /issuer}), with real ES256 tokens
 * and Postgres: authentication and the {@code SecurityConfig} patterns of {@code /{id}}, the PDP, the
 * context path in {@code Location} and {@code instance} (D11), ETag and {@code If-Match}, and the contract's
 * DoctorID v1 example (AC-02) on a type file that declares its schema URI.
 *
 * <p>Uses the pre-registered {@code e2e-tenant-a}/{@code e2e-tenant-b} schemas ({@code TenantDomainWebFilter}
 * rejects an unregistered tenant), and empties the catalog of tenant A around each test.
 */
class AttestationCatalogHttpIT extends PostgresIntegrationBase {

    private static final String TENANT_A = "e2e-tenant-a";
    private static final String TENANT_B = "e2e-tenant-b";
    private static final String ADMIN_ORG_ID = "admin-org-for-catalog-it";
    private static final String OPERATOR_ORG_ID = "operator-org-for-catalog-it";

    private static final String CATALOG = "/api/v1/attestation-catalog";
    private static final String DOCTORID = "doctorid.sd.1";
    private static final String DOCTORID_URI = "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt";
    private static final String DOCTORID_PATH = CATALOG + "/" + DOCTORID;

    /** The body of the DoctorID example of the contract (POST /api/v1/attestation-catalog). */
    private static final String CONTRACT_EXAMPLE = """
            {
              "schema_uri": "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt",
              "enabled": true,
              "delivery_modes": ["email", "ui"],
              "validity": { "default_days": 36500, "requester_can_set_dates": false },
              "subject": { "fields": [["givenName"], ["familyName"]], "separator": " " },
              "search_identifiers": [ { "name": "colegiado", "field": ["personal_administrative_number"] } ]
            }""";

    /** The same configuration, as a replace body (no schema). */
    private static final String CONTRACT_CONFIGURATION = """
            {
              "enabled": true,
              "delivery_modes": ["email", "ui"],
              "validity": { "default_days": 36500, "requester_can_set_dates": false },
              "subject": { "fields": [["givenName"], ["familyName"]], "separator": " " },
              "search_identifiers": [ { "name": "colegiado", "field": ["personal_administrative_number"] } ]
            }""";

    @DynamicPropertySource
    static void useCatalogProfiles(DynamicPropertyRegistry registry) {
        registry.add("credential.profiles.path", () -> "classpath:catalog-profiles");
    }

    @BeforeEach
    void seedTenants() {
        seedAdminOrganizationId(TENANT_A);
        seedAdminOrganizationId(TENANT_B);
        emptyCatalog(TENANT_A);
    }

    @AfterEach
    void cleanUp() {
        emptyCatalog(TENANT_A);
    }

    // ---- AC-02: the contract example ------------------------------------------------

    @Test
    void contractExample_isCreatedReadReplacedAndDisabledThroughTheEntryPaths() {
        String admin = administratorToken(TENANT_A);

        // POST: 201, Location relative to the host root with the context path, strong ETag.
        WebTestClient.ResponseSpec created = post(admin, CONTRACT_EXAMPLE);
        created.expectStatus().isCreated()
                .expectHeader().valueEquals(HttpHeaders.LOCATION, "/issuer" + DOCTORID_PATH)
                .expectHeader().valueEquals(HttpHeaders.ETAG, "\"0\"")
                .expectBody()
                .jsonPath("$.credential_configuration_id").isEqualTo(DOCTORID)
                .jsonPath("$.schema_uri").isEqualTo(DOCTORID_URI)
                .jsonPath("$.enabled").isEqualTo(true)
                .jsonPath("$.delivery_modes[0]").isEqualTo("email")
                .jsonPath("$.delivery_modes[1]").isEqualTo("ui")
                .jsonPath("$.validity.default_days").isEqualTo(36500)
                .jsonPath("$.validity.requester_can_set_dates").isEqualTo(false)
                .jsonPath("$.validity.max_days").doesNotExist()
                .jsonPath("$.subject.fields[0][0]").isEqualTo("givenName")
                .jsonPath("$.subject.fields[1][0]").isEqualTo("familyName")
                .jsonPath("$.subject.separator").isEqualTo(" ")
                .jsonPath("$.search_identifiers[0].name").isEqualTo("colegiado")
                .jsonPath("$.search_identifiers[0].field[0]").isEqualTo("personal_administrative_number")
                .jsonPath("$.created").value(IsoDateTime::assertIso8601WithOffset)
                .jsonPath("$.updated").value(IsoDateTime::assertIso8601WithOffset);

        // GET /{id}: stored and returned as given.
        get(admin, DOCTORID_PATH)
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ETAG, "\"0\"")
                .expectBody()
                .jsonPath("$.validity.default_days").isEqualTo(36500)
                .jsonPath("$.subject.fields[1][0]").isEqualTo("familyName")
                .jsonPath("$.search_identifiers[0].field[0]").isEqualTo("personal_administrative_number");

        // PUT /{id} with the ETag of the entry: new configuration, new ETag.
        String replacement = CONTRACT_CONFIGURATION.replace("36500", "100");
        put(admin, DOCTORID_PATH, "\"0\"", replacement)
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ETAG, "\"1\"")
                .expectBody().jsonPath("$.validity.default_days").isEqualTo(100);

        // PATCH /{id} with the ETag that PUT returned, no GET in between.
        patch(admin, DOCTORID_PATH, "\"1\"", "{\"enabled\": false}")
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ETAG, "\"2\"")
                .expectBody().jsonPath("$.enabled").isEqualTo(false);

        // The disabled entry is listed under enabled=false and not under enabled=true.
        get(admin, CATALOG + "?enabled=false")
                .expectStatus().isOk()
                .expectBody().jsonPath("$.length()").isEqualTo(1).jsonPath("$[0].credential_configuration_id").isEqualTo(DOCTORID);
        get(admin, CATALOG + "?enabled=true")
                .expectStatus().isOk()
                .expectBody().json("[]", true);
    }

    @Test
    void replace_withAStaleETag_isPreconditionFailedWithTheContextPathInTheInstance() {
        String admin = administratorToken(TENANT_A);
        post(admin, CONTRACT_EXAMPLE).expectStatus().isCreated();
        put(admin, DOCTORID_PATH, "\"0\"", CONTRACT_CONFIGURATION).expectStatus().isOk();

        put(admin, DOCTORID_PATH, "\"0\"", CONTRACT_CONFIGURATION)
                .expectStatus().isEqualTo(412)
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("precondition_failed")
                .jsonPath("$.instance").isEqualTo("/issuer" + DOCTORID_PATH);
    }

    @Test
    void replace_withoutIfMatch_isPreconditionRequiredNotBadRequest() {
        String admin = administratorToken(TENANT_A);
        post(admin, CONTRACT_EXAMPLE).expectStatus().isCreated();

        webTestClient().put().uri(DOCTORID_PATH)
                .headers(headers(admin, TENANT_A))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(CONTRACT_CONFIGURATION)
                .exchange()
                .expectStatus().isEqualTo(428)
                .expectBody().jsonPath("$.type").isEqualTo("precondition_required");
    }

    @Test
    void create_theSameSchemaTwice_isConflict() {
        String admin = administratorToken(TENANT_A);
        post(admin, CONTRACT_EXAMPLE).expectStatus().isCreated();

        post(admin, CONTRACT_EXAMPLE)
                .expectStatus().isEqualTo(409)
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("catalog_entry_already_exists")
                .jsonPath("$.instance").isEqualTo("/issuer" + CATALOG);
    }

    @Test
    void get_anEntryThatDoesNotExist_isNotFound() {
        get(administratorToken(TENANT_A), CATALOG + "/nothing.sd.1")
                .expectStatus().isNotFound()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("catalog_entry_not_found")
                .jsonPath("$.instance").isEqualTo("/issuer" + CATALOG + "/nothing.sd.1");
    }

    // ---- the entry the platform seeds with only its id (D13) -------------------------

    @Test
    void seededEntryWithOnlyItsId_isFilledOnReadAndThenReplaced() {
        seedEntryWithOnlyItsId(TENANT_A, DOCTORID);
        String admin = administratorToken(TENANT_A);

        // Read: completed from the type file, with the real schema URI of the file.
        String eTag = get(admin, DOCTORID_PATH)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.schema_uri").isEqualTo(DOCTORID_URI)
                .jsonPath("$.enabled").isEqualTo(true)
                .jsonPath("$.delivery_modes[0]").isEqualTo("email")
                .jsonPath("$.delivery_modes[1]").isEqualTo("ui")
                .jsonPath("$.validity.default_days").isEqualTo(36500)
                .jsonPath("$.validity.requester_can_set_dates").isEqualTo(false)
                .jsonPath("$.subject.fields[0][0]").isEqualTo("givenName")
                .jsonPath("$.subject.fields[1][0]").isEqualTo("familyName")
                .jsonPath("$.search_identifiers.length()").isEqualTo(0)
                .returnResult().getResponseHeaders().getETag();
        assertThat(eTag).isNotNull();

        // Replace with the contract's data, using the ETag read just now.
        put(admin, DOCTORID_PATH, eTag, CONTRACT_CONFIGURATION.replace("36500", "50"))
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.validity.default_days").isEqualTo(50)
                .jsonPath("$.search_identifiers[0].name").isEqualTo("colegiado");
        get(admin, DOCTORID_PATH)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.validity.default_days").isEqualTo(50)
                .jsonPath("$.search_identifiers[0].field[0]").isEqualTo("personal_administrative_number");
    }

    // ---- AC-04: fields that are not in the schema ------------------------------------

    @ParameterizedTest
    @CsvSource({"registrationNumber", "nationalId"})
    void create_withASearchIdentifierOutsideTheSchema_isFieldNotInSchema(String field) {
        String body = CONTRACT_EXAMPLE.replace(
                "{ \"name\": \"colegiado\", \"field\": [\"personal_administrative_number\"] } ]",
                "{ \"name\": \"colegiado\", \"field\": [\"personal_administrative_number\"] },"
                        + " { \"name\": \"dni\", \"field\": [\"" + field + "\"] } ]");

        post(administratorToken(TENANT_A), body)
                .expectStatus().isBadRequest()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("field_not_in_schema")
                .jsonPath("$.detail").isEqualTo("Field [" + field + "] is not in the schema")
                .jsonPath("$.instance").isEqualTo("/issuer" + CATALOG)
                .jsonPath("$.violations[0].field").isEqualTo("search_identifiers[1].field");
    }

    // ---- authentication, the PDP and the tenant ---------------------------------------

    @Test
    void withoutAToken_everyOperationIsUnauthorizedProblem() {
        for (HttpMethod method : List.of(HttpMethod.GET, HttpMethod.PUT, HttpMethod.PATCH)) {
            webTestClient().method(method).uri(DOCTORID_PATH)
                    .header(X_TENANT_HEADER, TENANT_A)
                    .exchange()
                    .expectStatus().isUnauthorized()
                    .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON);
        }
    }

    @Test
    void operator_readsTheCatalog() {
        post(administratorToken(TENANT_A), CONTRACT_EXAMPLE).expectStatus().isCreated();
        String operator = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        get(operator, CATALOG).expectStatus().isOk().expectBody().jsonPath("$[0].credential_configuration_id").isEqualTo(DOCTORID);
        get(operator, DOCTORID_PATH).expectStatus().isOk();
    }

    @Test
    void operator_writeIsInsufficientPermissionEvenWithAMalformedBodyOrAnInvalidConfiguration() {
        String operator = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        for (String body : List.of("{this is not json", "{\"enabled\": true, \"delivery_modes\": []}")) {
            post(operator, body)
                    .expectStatus().isForbidden()
                    .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                    .expectBody().jsonPath("$.type").isEqualTo("insufficient_permission");
            put(operator, DOCTORID_PATH, "\"0\"", body)
                    .expectStatus().isForbidden()
                    .expectBody().jsonPath("$.type").isEqualTo("insufficient_permission");
        }
        patch(operator, DOCTORID_PATH, "\"0\"", "{\"enabled\": false}")
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("insufficient_permission");
    }

    @Test
    void administratorWithMalformedBody_isBadRequestProblem() {
        post(administratorToken(TENANT_A), "{this is not json")
                .expectStatus().isBadRequest()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.instance").isEqualTo("/issuer" + CATALOG);
    }

    @Test
    void tokenOfAnotherTenant_isTenantMismatch() {
        String adminOfB = administratorToken(TENANT_B);

        webTestClient().get().uri(CATALOG)
                .headers(headers(adminOfB, TENANT_A))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody().jsonPath("$.type").isEqualTo("tenant_mismatch");
    }

    // ---- helpers ----------------------------------------------------------------------

    private WebTestClient.ResponseSpec get(String token, String uri) {
        return webTestClient().get().uri(uri).headers(headers(token, TENANT_A)).exchange();
    }

    private WebTestClient.ResponseSpec post(String token, String body) {
        return webTestClient().post().uri(CATALOG)
                .headers(headers(token, TENANT_A))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    private WebTestClient.ResponseSpec put(String token, String uri, String ifMatch, String body) {
        return webTestClient().put().uri(uri)
                .headers(headers(token, TENANT_A))
                .header(HttpHeaders.IF_MATCH, ifMatch)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    private WebTestClient.ResponseSpec patch(String token, String uri, String ifMatch, String body) {
        return webTestClient().patch().uri(uri)
                .headers(headers(token, TENANT_A))
                .header(HttpHeaders.IF_MATCH, ifMatch)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    private static Consumer<HttpHeaders> headers(String token, String tenant) {
        return headers -> {
            headers.setBearerAuth(token);
            headers.set(X_TENANT_HEADER, tenant);
        };
    }

    /** The tenant's administrator: administrator organization with Onboarding/Execute over the tenant's domain. */
    private String administratorToken(String tenant) {
        return mintUserAccessToken(tenant, ADMIN_ORG_ID, List.of(Map.of(
                "type", "organization",
                "domain", tenant,
                "function", "Onboarding",
                "action", List.of("Execute"))));
    }

    private void seedAdminOrganizationId(String tenant) {
        databaseClient.sql("INSERT INTO \"" + tenant + SCHEMA_SUFFIX + "\".tenant_config (config_key, config_value) "
                        + "VALUES ('admin_organization_id', :value) "
                        + "ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value")
                .bind("value", ADMIN_ORG_ID)
                .then().block();
    }

    private void seedEntryWithOnlyItsId(String tenant, String credentialConfigurationId) {
        databaseClient.sql("INSERT INTO \"" + tenant + SCHEMA_SUFFIX + "\".tenant_credential_profile "
                        + "(credential_configuration_id, enabled) VALUES (:id, true)")
                .bind("id", credentialConfigurationId)
                .then().block();
    }

    private void emptyCatalog(String tenant) {
        databaseClient.sql("DELETE FROM \"" + tenant + SCHEMA_SUFFIX + "\".tenant_credential_profile").then().block();
    }

    private static final class IsoDateTime {
        private IsoDateTime() {
        }

        static void assertIso8601WithOffset(Object value) {
            assertThat(OffsetDateTime.parse(String.valueOf(value))).isNotNull();
        }
    }
}
