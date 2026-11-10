package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.support.ContractSchemas;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atMostOnce;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * EUD-268: {@code POST /api/v1/issuances} over real HTTP (server under {@code /issuer}), with real ES256
 * tokens, Postgres and the tenant's catalog entry, against the EUD-254 contract.
 *
 * <ul>
 *   <li>A successful delivery is a 200 with one entry in {@code responses} and one issuance process, of the
 *       organization the request decides, valid for the window it asked for.</li>
 *   <li>Each rejection is its contract code and status, served as {@code application/problem+json},
 *       conforming to the contract's {@code Problem} schema, and leaves no issuance process created.</li>
 * </ul>
 *
 * <p>Every request but the one under test is valid: a DoctorID enabled in the catalog of
 * {@code e2e-tenant-a} for email and ui, whose entry lets the requester set the dates up to 365 days,
 * requested by an organization administrator. The email itself is not sent ({@link EmailService} is a mock).
 * The delivery failures (503/500) join when the delivery flow is reduced to one mode; {@code invalid_holder_key}
 * is covered by HolderKeyTest, since the only types that take a holder key here (the machine LEAR types)
 * carry powers whose grant rules are not this order's.
 */
class IssuanceContractIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-a";
    private static final String OTHER_TENANT = "e2e-tenant-b";
    private static final String ORGANIZATION = "VATES-B11111111";
    private static final String OTHER_ORGANIZATION = "VATES-B22222222";
    private static final String ISSUANCES = "/api/v1/issuances";
    private static final String CATALOG = "/api/v1/attestation-catalog";
    private static final String DOCTORID = "doctorid.sd.1";

    /** The tenant's DoctorID entry: email and ui, dates settable by the requester up to 365 days. */
    private static final String DOCTORID_ENTRY = """
            {
              "schema_uri": "https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt",
              "enabled": true,
              "delivery_modes": ["email", "ui"],
              "validity": { "default_days": 30, "requester_can_set_dates": true, "max_days": 365 },
              "subject": { "fields": [["givenName"], ["familyName"]], "separator": " " },
              "search_identifiers": []
            }""";

    private static final String VALID_PAYLOAD = """
            {"givenName": "Jane", "familyName": "Doe", "personal_administrative_number": "123456789",
             "medical_speciality": ["Cardiology"]}""";

    private static final String HOLDER_EMAIL = "jane.doe@example.org";
    private static final String FRONTEND_URL_KEY = "issuer.frontend_url";

    @MockitoBean
    private EmailService emailService;

    private boolean seededFrontendUrl;

    @DynamicPropertySource
    static void useCatalogProfiles(DynamicPropertyRegistry registry) {
        registry.add("credential.profiles.path", () -> "classpath:catalog-profiles");
    }

    @BeforeEach
    void enableDoctorId() {
        emptyCatalog();
        deleteIssuancesOfTheHolder();
        seededFrontendUrl = seedFrontendUrlIfAbsent();
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(Mono.empty());
        when(emailService.sendBrandedCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), any()))
                .thenReturn(Mono.empty());
        webTestClient().post().uri(CATALOG)
                .headers(headers(tenantAdministratorToken(TENANT), TENANT))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(DOCTORID_ENTRY)
                .exchange()
                .expectStatus().isCreated();
    }

    @AfterEach
    void cleanUp() {
        emptyCatalog();
        deleteIssuancesOfTheHolder();
        if (seededFrontendUrl) {
            databaseClient.sql("DELETE FROM \"" + TENANT + SCHEMA_SUFFIX + "\".tenant_config WHERE config_key = :key")
                    .bind("key", FRONTEND_URL_KEY).then().block();
        }
    }

    // ---- 200 -------------------------------------------------------------------------

    @Test
    void aRequestWithUiIsA200WithTheOfferLinkAndOneDraftProcess() {
        accepted(request("\"delivery\": \"ui\""))
                .jsonPath("$.responses.length()").isEqualTo(1)
                .jsonPath("$.responses[0].channel").isEqualTo("ui")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].error").doesNotExist()
                .jsonPath("$.responses[0].body.credential_offer_uri")
                .value(uri -> assertThat(uri.toString()).startsWith("openid-credential-offer://"));

        Map<String, Object> process = theOnlyProcessOfTheHolder();
        assertThat(process).containsEntry("credential_status", "DRAFT")
                .containsEntry("delivery", "ui")
                .containsEntry("organization_identifier", ORGANIZATION);
        verifyNoInteractions(emailService);
    }

    @Test
    void aRequestWithEmailIsA200AndTheOfferGoesToTheHolder() {
        accepted(request("\"delivery\": \"email\""))
                .jsonPath("$.responses.length()").isEqualTo(1)
                .jsonPath("$.responses[0].channel").isEqualTo("email")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body").doesNotExist();

        assertThat(theOnlyProcessOfTheHolder()).containsEntry("delivery", "email");
        verify(emailService, atMostOnce()).sendCredentialOfferEmail(eq(HOLDER_EMAIL), anyString(), anyString(), any(), any());
        verify(emailService, atMostOnce()).sendBrandedCredentialOfferEmail(eq(HOLDER_EMAIL), anyString(), anyString(), anyString(), any());
        assertThat(mockingDetails(emailService).getInvocations()).as("offer emails sent").hasSize(1);
    }

    @Test
    void aRequestWithoutDeliveryIsDeliveredByEmail() {
        accepted("""
                {"credential_configuration_id": "doctorid.sd.1", "email": "%s", "payload": %s}"""
                .formatted(HOLDER_EMAIL, VALID_PAYLOAD))
                .jsonPath("$.responses[0].channel").isEqualTo("email");
    }

    /** PRD AC-15: the process belongs to the indicated organization, whose administrator then sees it. */
    @Test
    void aTenantAdministratorIssuingForAnotherOrganizationLeavesTheProcessInThatOrganization() {
        accepted(tenantAdministratorToken(TENANT),
                request("\"delivery\": \"ui\", \"organization\": \"" + OTHER_ORGANIZATION + "\""));

        Map<String, Object> process = theOnlyProcessOfTheHolder();
        assertThat(process).containsEntry("organization_identifier", OTHER_ORGANIZATION);
        String id = process.get("issuance_id").toString();
        webTestClient().get().uri(ISSUANCES + "/{id}", id)
                .headers(headers(mintOperatorAccessToken(TENANT, OTHER_ORGANIZATION), TENANT))
                .exchange()
                .expectStatus().isOk();
        webTestClient().get().uri(ISSUANCES + "/{id}", id)
                .headers(headers(organizationAdministratorToken(TENANT), TENANT))
                .exchange()
                .expectStatus().isNotFound();
    }

    /** PRD AC-09: an entry that lets the requester set the dates issues for the window asked for. */
    @Test
    void aValidityWithinTheMaximumIsTheValidityOfTheAttestation() {
        accepted(requestWithPayload("""
                {"givenName": "Jane", "familyName": "Doe", "personal_administrative_number": "123456789",
                 "medical_speciality": ["Cardiology"],
                 "validFrom": "2030-01-01T00:00:00Z", "validUntil": "2030-03-01T00:00:00Z"}""",
                "\"delivery\": \"ui\""));

        assertThat(theOnlyProcessOfTheHolder().get("credential_data_set").toString())
                .contains("2030-01-01T00:00:00Z", "2030-03-01T00:00:00Z");
    }

    // ---- 400 -------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"email,ui", "direct,email", "fax", "EMAIL", "", " email "})
    void aDeliveryOtherThanExactlyOneModeIsInvalidDeliveryMode(String delivery) {
        rejected(request("\"delivery\": \"" + delivery + "\""), HttpStatus.BAD_REQUEST, "invalid_delivery_mode")
                .jsonPath("$.detail").isEqualTo("delivery must be one of: email, ui, direct");
    }

    @ParameterizedTest
    @ValueSource(strings = {"client_credentials", "refresh_token", "Authorization_Code", ""})
    void aGrantOtherThanItsTwoValuesIsInvalidGrantType(String grantType) {
        rejected(request("\"delivery\": \"ui\", \"grant_type\": \"" + grantType + "\""),
                HttpStatus.BAD_REQUEST, "invalid_grant_type");
    }

    @Test
    void aValidityAboveTheMaximumOfTheEntryIsInvalidValidity() {
        rejected(requestWithPayload("""
                {"givenName": "Jane", "familyName": "Doe", "personal_administrative_number": "123456789",
                 "medical_speciality": ["Cardiology"],
                 "validFrom": "2030-01-01T00:00:00Z", "validUntil": "2031-06-01T00:00:00Z"}"""),
                HttpStatus.BAD_REQUEST, "invalid_validity");
    }

    @Test
    void aValidityEndNotAfterItsStartIsInvalidValidity() {
        rejected(requestWithPayload("""
                {"givenName": "Jane", "familyName": "Doe", "personal_administrative_number": "123456789",
                 "medical_speciality": ["Cardiology"],
                 "validFrom": "2030-01-01T00:00:00Z", "validUntil": "2029-01-01T00:00:00Z"}"""),
                HttpStatus.BAD_REQUEST, "invalid_validity");
    }

    @Test
    void aMissingEmailIsABadRequestNamingTheField() {
        rejected("""
                {"credential_configuration_id": "doctorid.sd.1", "delivery": "email", "payload": %s}"""
                .formatted(VALID_PAYLOAD), HttpStatus.BAD_REQUEST, "BAD_REQUEST")
                .jsonPath("$.violations[0].field").isEqualTo("email");
    }

    @Test
    void aMissingCredentialConfigurationIdIsABadRequestNamingTheField() {
        rejected("""
                {"email": "jane.doe@example.org", "payload": %s}""".formatted(VALID_PAYLOAD),
                HttpStatus.BAD_REQUEST, "BAD_REQUEST")
                .jsonPath("$.violations[0].field").isEqualTo("credential_configuration_id");
    }

    @Test
    void anUnknownTypeIsUnsupportedCredentialType() {
        rejected("""
                {"credential_configuration_id": "no.such.type.1", "email": "jane.doe@example.org", "payload": %s}"""
                .formatted(VALID_PAYLOAD), HttpStatus.BAD_REQUEST, "unsupported_credential_type");
    }

    @Test
    void aPayloadWithoutARequiredAttributeIsPayloadValidationErrorNamingIt() {
        rejected(requestWithPayload("""
                {"givenName": "Jane", "familyName": "Doe", "personal_administrative_number": "123456789"}"""),
                HttpStatus.BAD_REQUEST, "payload_validation_error")
                .jsonPath("$.violations").isNotEmpty();
    }

    /**
     * EUD-254 §5: a request carrying valid dates goes past the schema and is stopped at the grant. The
     * DoctorID schema admits additional attributes, so this does not prove by itself that the dates are
     * split before the schema: IssuanceWorkflowImplTest checks that the validator gets the payload without them.
     */
    @Test
    void aRequestWithValidDatesReachesTheChecksAfterTheSchema() {
        rejected(requestWithPayload("""
                {"givenName": "Jane", "familyName": "Doe", "personal_administrative_number": "123456789",
                 "medical_speciality": ["Cardiology"],
                 "validFrom": "2030-01-01T00:00:00Z", "validUntil": "2030-02-01T00:00:00Z"}""",
                "\"grant_type\": \"client_credentials\""),
                // The request goes past the schema and is stopped at the grant: the dates did not fail it.
                HttpStatus.BAD_REQUEST, "invalid_grant_type");
    }

    // ---- 403 -------------------------------------------------------------------------

    @Test
    void anOrganizationAdministratorIndicatingAnotherOrganizationIsInsufficientPermission() {
        rejected(organizationAdministratorToken(TENANT), TENANT,
                request("\"delivery\": \"email\", \"organization\": \"" + OTHER_ORGANIZATION + "\""),
                HttpStatus.FORBIDDEN, "insufficient_permission");
    }

    @Test
    void aTokenOfAnotherTenantIsTenantMismatch() {
        rejected(organizationAdministratorToken(OTHER_TENANT), TENANT, request("\"delivery\": \"email\""),
                HttpStatus.FORBIDDEN, "tenant_mismatch");
    }

    // ---- helpers ----------------------------------------------------------------------

    private static String request(String extraFields) {
        return """
                {"credential_configuration_id": "doctorid.sd.1", "email": "jane.doe@example.org",
                 "payload": %s, %s}""".formatted(VALID_PAYLOAD, extraFields);
    }

    private static String requestWithPayload(String payload) {
        return requestWithPayload(payload, "\"delivery\": \"email\"");
    }

    private static String requestWithPayload(String payload, String extraFields) {
        return """
                {"credential_configuration_id": "doctorid.sd.1", "email": "jane.doe@example.org",
                 "payload": %s, %s}""".formatted(payload, extraFields);
    }

    private WebTestClient.BodyContentSpec accepted(String body) {
        return accepted(organizationAdministratorToken(TENANT), body);
    }

    /** A 200 {@code application/json} {@code IssuanceResponse}, and exactly one process of the holder created. */
    private WebTestClient.BodyContentSpec accepted(String token, String body) {
        WebTestClient.BodyContentSpec response = webTestClient().post().uri(ISSUANCES)
                .headers(headers(token, TENANT))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectBody();
        theOnlyProcessOfTheHolder();
        return response;
    }

    private Map<String, Object> theOnlyProcessOfTheHolder() {
        List<Map<String, Object>> rows = databaseClient.sql("SELECT issuance_id, credential_status, delivery, "
                        + "organization_identifier, credential_data_set FROM \"" + TENANT + SCHEMA_SUFFIX
                        + "\".issuance WHERE email = :email")
                .bind("email", HOLDER_EMAIL)
                .fetch().all().collectList().block();
        assertThat(rows).as("issuance processes of the holder").hasSize(1);
        return rows.getFirst();
    }

    private void deleteIssuancesOfTheHolder() {
        databaseClient.sql("DELETE FROM \"" + TENANT + SCHEMA_SUFFIX + "\".issuance WHERE email = :email")
                .bind("email", HOLDER_EMAIL).then().block();
    }

    /** The email offer links to the tenant's frontend; seeded only when the tenant has none. */
    private boolean seedFrontendUrlIfAbsent() {
        Long rows = databaseClient.sql("INSERT INTO \"" + TENANT + SCHEMA_SUFFIX + "\".tenant_config "
                        + "(config_key, config_value) VALUES (:key, 'https://e2e-tenant-a.example.org') "
                        + "ON CONFLICT (config_key) DO NOTHING")
                .bind("key", FRONTEND_URL_KEY)
                .fetch().rowsUpdated().block();
        return rows != null && rows > 0;
    }

    private WebTestClient.BodyContentSpec rejected(String body, HttpStatus status, String type) {
        return rejected(organizationAdministratorToken(TENANT), TENANT, body, status, type);
    }

    /**
     * The request is rejected with {@code type} and {@code status} as a contract Problem, and no issuance
     * process of the tenant was created.
     */
    private WebTestClient.BodyContentSpec rejected(String token, String tenant, String body, HttpStatus status,
                                                   String type) {
        long before = issuanceCount();
        WebTestClient.BodyContentSpec response = webTestClient().post().uri(ISSUANCES)
                .headers(headers(token, tenant))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isEqualTo(status)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectHeader().doesNotExist(HttpHeaders.LOCATION)
                .expectBody()
                .consumeWith(conformsTo("Problem"))
                .jsonPath("$.type").isEqualTo(type)
                .jsonPath("$.status").isEqualTo(status.value())
                .jsonPath("$.title").isNotEmpty();
        assertThat(issuanceCount()).as("issuance processes created by a rejected request").isEqualTo(before);
        return response;
    }

    private long issuanceCount() {
        Long count = databaseClient.sql("SELECT count(*) AS n FROM \"" + TENANT + SCHEMA_SUFFIX + "\".issuance")
                .map(row -> row.get("n", Long.class))
                .one()
                .block();
        return count != null ? count : 0;
    }

    private void emptyCatalog() {
        databaseClient.sql("DELETE FROM \"" + TENANT + SCHEMA_SUFFIX + "\".tenant_credential_profile").then().block();
    }

    private static Consumer<HttpHeaders> headers(String token, String tenant) {
        return headers -> {
            headers.setBearerAuth(token);
            headers.set(X_TENANT_HEADER, tenant);
        };
    }

    /** An organization administrator: {@code domain · <tenant> · Onboarding · Execute}. */
    private String organizationAdministratorToken(String tenant) {
        return mintOperatorAccessToken(tenant, ORGANIZATION);
    }

    /** The tenant's administrator: {@code organization · <tenant> · Onboarding · Execute} (EUD-272). */
    private String tenantAdministratorToken(String tenant) {
        return mintUserAccessToken(tenant, "admin-org-for-issuance-contract-it", List.of(Map.of(
                "type", "organization",
                "domain", tenant,
                "function", "Onboarding",
                "action", List.of("Execute"))));
    }

    private static Consumer<EntityExchangeResult<byte[]>> conformsTo(String schemaName) {
        return result -> {
            assertThat(result.getResponseBody()).as("response body").isNotNull();
            ContractSchemas.assertConforms(schemaName, new String(result.getResponseBody(), StandardCharsets.UTF_8));
        };
    }
}
