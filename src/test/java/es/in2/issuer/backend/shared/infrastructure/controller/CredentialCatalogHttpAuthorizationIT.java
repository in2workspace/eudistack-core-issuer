package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.CREDENTIAL_CATALOG_PATH;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Closes TD-3 / TDG-24: the missing HTTP -&gt; authentication -&gt; authorization -&gt; DB
 * integration coverage for the catalog's lowest-privilege role (the tenant's operator,
 * {@code LEAR}, opened by AD-16). Every other test in the Story either bypasses HTTP
 * entirely ({@code CredentialCatalogTransactionalIT} invokes the domain service
 * directly) or mocks {@code AuthorizationContext} ({@code CredentialCatalogControllerTest}).
 *
 * <p>Here the bearer token is a real, ES256-signed JWT minted via
 * {@link PostgresIntegrationBase#mintOperatorAccessToken} -- the same signing key
 * {@code CustomAuthenticationManager} verifies against, so this exercises the actual
 * authentication filter and {@code AccessTokenServiceImpl.resolveRole}, not a
 * hand-crafted token injected past them.
 *
 * <p>Uses the pre-registered {@code e2e-tenant-a}/{@code e2e-tenant-b} schemas (not a
 * private throwaway schema): {@code TenantDomainWebFilter} rejects any tenant absent from
 * {@code tenant_registry} with a 404 before the request ever reaches this controller, so
 * -- unlike {@code TenantDeliveryModesMigrationIT}, which drives Flyway directly below the
 * HTTP layer -- an unregistered schema does not work here. Shares these two schemas with
 * {@code CredentialCatalogTransactionalIT}, which only ever calls the domain service
 * directly and never touches {@code tenant_config}/{@code admin_organization_id}, so this
 * class's own seeding cannot affect its assertions; both classes reset the catalog's
 * enabled set explicitly before each test, so execution order does not matter either.
 */
class CredentialCatalogHttpAuthorizationIT extends PostgresIntegrationBase {

    private static final String TENANT_A = "e2e-tenant-a";
    private static final String TENANT_B = "e2e-tenant-b";
    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String SECOND_CONFIG_ID = "gx.labelcredential.w3c.2";
    private static final String ADMIN_ORG_ID = "admin-org-for-authz-it";
    private static final String OPERATOR_ORG_ID = "operator-org-for-authz-it";

    @BeforeEach
    void seedTenants() {
        seedAdminOrganizationId(TENANT_A);
        seedAdminOrganizationId(TENANT_B);
        emptyCatalog(TENANT_A);
        seedEnabledProfile(TENANT_A);
    }

    @AfterEach
    void cleanUp() {
        emptyCatalog(TENANT_A);
    }

    @Test
    void operator_readsOwnTenantCatalog_returns200() {
        String token = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        webTestClient()
                .get().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_A)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void operator_attemptsWrite_returns403WithoutReachingTheService() {
        String token = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        webTestClient()
                .put().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_A)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"" + CONFIG_ID + "\"]}")
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("insufficient_permission")
                .jsonPath("$.instance").isEqualTo("/issuer" + CREDENTIAL_CATALOG_PATH);
    }

    /** AC-11 for the alias as well: the PDP answers before the body is looked at. */
    @Test
    void operator_attemptsWriteWithAMalformedBody_stillGets403() {
        String token = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        webTestClient()
                .put().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_A)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{this is not json")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("insufficient_permission");
    }

    @Test
    void alias_carriesTheDeprecationHeadersWithTheContextPathInTheSuccessorLink() {
        String token = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        webTestClient()
                .get().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_A)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Deprecation", "@1792368000")
                .expectHeader().valueEquals(HttpHeaders.LINK, "</issuer/api/v1/attestation-catalog>; rel=\"successor-version\"");
    }

    /**
     * D5: the PUT leaves out a type: it is disabled, not deleted. The portal's GET still lists it, now with
     * {@code enabled=false}, and the row keeps its configuration, so the attestation catalog API still has
     * the entry, disabled and with its version bumped.
     */
    @Test
    void tenantAdmin_putsWithoutAType_disablesItAndTheGetStillListsItAsDisabled() {
        String token = mintAdminAccessToken(TENANT_A, TENANT_A);
        putCatalog(token, TENANT_A, CONFIG_ID, SECOND_CONFIG_ID).expectStatus().isOk();

        putCatalog(token, TENANT_A, CONFIG_ID).expectStatus().isOk();

        webTestClient()
                .get().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_A)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[?(@.credentialConfigurationId=='" + CONFIG_ID + "')].enabled").isEqualTo(true)
                .jsonPath("$[?(@.credentialConfigurationId=='" + SECOND_CONFIG_ID + "')].enabled").isEqualTo(false);
        assertThat(rowsOf(TENANT_A)).containsEntry(CONFIG_ID, true).containsEntry(SECOND_CONFIG_ID, false);
        webTestClient()
                .get().uri("/api/v1/attestation-catalog/" + SECOND_CONFIG_ID)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_A)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ETAG, "\"1\"")
                .expectBody().jsonPath("$.enabled").isEqualTo(false);
    }

    /** D8: above the schema ceiling is a 400 BAD_REQUEST now, not the 409 delivery_mode_not_eligible. */
    @Test
    void tenantAdmin_putsADeliveryModeAboveTheSchemaCeiling_returns400BadRequest() {
        String token = mintAdminAccessToken(TENANT_A, TENANT_A);

        webTestClient()
                .put().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_A)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[\"" + CONFIG_ID + "\"],"
                        + "\"deliveryModesByConfigurationId\":{\"" + CONFIG_ID + "\":[\"direct\"]}}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.violations[0].field").isEqualTo("deliveryModesByConfigurationId");
    }

    @Test
    void tenantAdmin_writesOwnTenantCatalog_returns200() {
        String token = mintAdminAccessToken(TENANT_A, TENANT_A);

        putCatalog(token, TENANT_A)
                .expectStatus().isOk();
    }

    /** The administrator organization with Onboarding/Execute over another domain is not the
     *  tenant's administrator for the catalog write (D15): the power must carry the tenant's domain. */
    @Test
    void adminOrganizationWithPowerOnAnotherDomain_writes_returns403InsufficientPermission() {
        String token = mintAdminAccessToken(TENANT_A, TENANT_B);

        putCatalog(token, TENANT_A)
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("insufficient_permission");
    }

    @Test
    void tenantAdminTokenOfTenantA_writesTenantB_returns403TenantMismatch() {
        String token = mintAdminAccessToken(TENANT_A, TENANT_A);

        putCatalog(token, TENANT_B)
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.type").isEqualTo("tenant_mismatch");
    }

    /** NFR-S-169-04 (inter-tenant isolation, extended to the lowest-privilege role): a
     *  token genuinely minted for tenant A must not read tenant B's catalog just because
     *  the caller sends {@code X-Tenant: B} -- {@code requireTenantMatch()}'s S1 fix. */
    @Test
    void tokenMintedForTenantA_usedAgainstTenantB_returns403TenantMismatch() {
        String token = mintOperatorAccessToken(TENANT_A, OPERATOR_ORG_ID);

        webTestClient()
                .get().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT_B)
                .exchange()
                .expectStatus().isForbidden();
    }

    // ---- helpers ---------------------------------------------------------------

    private String mintAdminAccessToken(String tenantClaim, String powerDomain) {
        return mintUserAccessToken(tenantClaim, ADMIN_ORG_ID, List.of(Map.of(
                "type", "organization",
                "domain", powerDomain,
                "function", "Onboarding",
                "action", List.of("Execute"))));
    }

    private WebTestClient.ResponseSpec putCatalog(String token, String tenant) {
        return putCatalog(token, tenant, CONFIG_ID);
    }

    private WebTestClient.ResponseSpec putCatalog(String token, String tenant, String... configIds) {
        String ids = Arrays.stream(configIds).map(id -> "\"" + id + "\"").collect(Collectors.joining(","));
        return webTestClient()
                .put().uri(CREDENTIAL_CATALOG_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, tenant)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"enabledConfigurationIds\":[" + ids + "]}")
                .exchange();
    }

    private void emptyCatalog(String tenant) {
        databaseClient.sql("DELETE FROM \"" + tenant + SCHEMA_SUFFIX + "\".tenant_credential_profile").then().block();
    }

    /** {@code credential_configuration_id} to {@code enabled}, straight from the tenant's table. */
    private Map<String, Boolean> rowsOf(String tenant) {
        return databaseClient.sql("SELECT credential_configuration_id, enabled FROM \"" + tenant
                        + SCHEMA_SUFFIX + "\".tenant_credential_profile")
                .map((row, metadata) -> Map.entry(
                        row.get("credential_configuration_id", String.class), row.get("enabled", Boolean.class)))
                .all().collectMap(Map.Entry::getKey, Map.Entry::getValue).block();
    }

    private void seedAdminOrganizationId(String tenant) {
        String schema = tenant + SCHEMA_SUFFIX;
        databaseClient.sql("INSERT INTO \"" + schema + "\".tenant_config (config_key, config_value) "
                        + "VALUES ('admin_organization_id', :value) "
                        + "ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value")
                .bind("value", ADMIN_ORG_ID)
                .then().block();
    }

    private void seedEnabledProfile(String tenant) {
        String schema = tenant + SCHEMA_SUFFIX;
        databaseClient.sql("INSERT INTO \"" + schema + "\".tenant_credential_profile "
                        + "(credential_configuration_id, enabled) VALUES (:configId, true) "
                        + "ON CONFLICT (credential_configuration_id) DO UPDATE SET enabled = true")
                .bind("configId", CONFIG_ID)
                .then().block();
    }
}
