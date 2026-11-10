package es.in2.issuer.backend.issuance.infrastructure.controller;

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
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-268: the rejections of {@code POST /api/v1/issuances} over real HTTP (server under {@code /issuer}),
 * with real ES256 tokens, Postgres and the tenant's catalog entry, against the EUD-254 contract: each one
 * is its contract code and status, served as {@code application/problem+json}, conforming to the
 * contract's {@code Problem} schema, and leaves no issuance process created.
 *
 * <p>Every request but the one under test is valid: a DoctorID enabled in the catalog of
 * {@code e2e-tenant-a} for email and ui, whose entry lets the requester set the dates up to 365 days,
 * requested by an organization administrator. The successful delivery and its failures (503/500) are
 * covered when the delivery flow is reduced to one mode.
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

    @DynamicPropertySource
    static void useCatalogProfiles(DynamicPropertyRegistry registry) {
        registry.add("credential.profiles.path", () -> "classpath:catalog-profiles");
    }

    @BeforeEach
    void enableDoctorId() {
        emptyCatalog();
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
