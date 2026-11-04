package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.json.JsonCompareMode;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * EUD-295: {@code POST /api/v1/issuances/{id}/credential-offer} through the real HTTP stack --
 * filters, authentication with a genuinely signed token, the renewal workflow, Postgres and the
 * in-memory offer and grant stores -- against the {@code renewCredentialOffer} contract.
 *
 * <p>The email service is a mock: the IT checks what is sent (and can make it fail) without SMTP.
 * The platform's read-only view (ES-04) needs the {@code platform} tenant, which the shared IT
 * registry does not register; it is covered by {@code CredentialOfferRenewalWorkflowImplTest}.
 */
@TestPropertySource(properties = "issuer.api.rate-limit.max-per-minute=" + CredentialOfferRenewalIT.RATE_LIMIT)
class CredentialOfferRenewalIT extends PostgresIntegrationBase {

    static final int RATE_LIMIT = 30;

    private static final String TENANT = "e2e-tenant-a";
    private static final String OTHER_TENANT = "e2e-tenant-b";
    private static final String ADMIN_ORG = "admin-org-for-renewal-it";
    private static final String OPERATOR_ORG = "operator-org-for-renewal-it";
    private static final String OTHER_ORG = "other-org-for-renewal-it";
    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String PRE_AUTHORIZED = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    private static final String HOLDER = "holder@example.com";
    /** The credential of a portal user, as the Verifier states it in the access token (the LEAR profile the IT registry loads). */
    private static final String PORTAL_CREDENTIAL_TYPE = "learcredential.employee.w3c.4";

    private static final Map<String, Object> ONBOARDING_EXECUTE =
            Map.of("type", "domain", "domain", "DOME", "function", "Onboarding", "action", List.of("Execute"));
    private static final Map<String, Object> PRODUCT_OFFERING =
            Map.of("type", "domain", "domain", "DOME", "function", "ProductOffering", "action", List.of("Create"));
    private static final Map<String, Object> SYSADMIN =
            Map.of("type", "organization", "domain", "EUDISTACK", "function", "System", "action", List.of("Administration"));

    @MockitoBean
    private EmailService emailService;

    /** Each test speaks from its own address, so the volume limit of one never reaches another. */
    private String clientIp;

    @BeforeEach
    void setUp() {
        clientIp = "10.%d.%d.%d".formatted(ThreadLocalRandom.current().nextInt(1, 255),
                ThreadLocalRandom.current().nextInt(1, 255), ThreadLocalRandom.current().nextInt(1, 255));
        seedTenantConfig(TENANT);
        seedTenantConfig(OTHER_TENANT);
        lenient().when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(Mono.empty());
        lenient().when(emailService.sendTxCodeNotification(anyString(), anyString())).thenReturn(Mono.empty());
    }

    // ── 200 ───────────────────────────────────────────────────────────────────────────────

    /** AC-01 and AC-05: a new offer with a new pre-authorized code; the previous offer and code no longer work. */
    @Test
    void renew_ui_returnsANewOfferAndVoidsThePreviousOneWithItsCode() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "ui", PRE_AUTHORIZED);
        String operator = operatorToken();
        long issuancesBefore = issuanceCount(TENANT, OPERATOR_ORG);

        String firstOffer = offerUri(renew(operator, id).expectStatus().isOk());
        JsonNode first = openOffer(firstOffer).expectStatus().isOk().expectBody(JsonNode.class).returnResult().getResponseBody();
        String firstCode = preAuthorizedCode(first);
        String firstPin = lastPin();

        JsonNode secondResponse = renew(operator, id)
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(JsonNode.class).returnResult().getResponseBody();
        assertThat(secondResponse).isNotNull();
        assertThat(secondResponse.path("responses")).hasSize(1);
        assertThat(secondResponse.path("responses").path(0).path("channel").asText()).isEqualTo("ui");
        assertThat(secondResponse.path("responses").path(0).path("status").asInt()).isEqualTo(200);
        String secondOffer = secondResponse.path("responses").path(0).path("body").path("credential_offer_uri").asText();

        assertThat(secondOffer).isNotEqualTo(firstOffer).startsWith("openid-credential-offer://?credential_offer_uri=");
        openOffer(firstOffer).expectStatus().isEqualTo(HttpStatus.GONE);
        token(firstCode, firstPin).expectStatus().isBadRequest();

        JsonNode second = openOffer(secondOffer).expectStatus().isOk().expectBody(JsonNode.class).returnResult().getResponseBody();
        token(preAuthorizedCode(second), lastPin()).expectStatus().isOk();
        verify(emailService, never()).sendCredentialOfferEmail(anyString(), anyString(), anyString(), any(), any());
        assertThat(issuanceStatus(TENANT, id)).isEqualTo("DRAFT");
        assertThat(issuanceCount(TENANT, OPERATOR_ORG)).isEqualTo(issuancesBefore);
    }

    /** AC-02: the new offer goes to the holder's email; the response has no body. */
    @Test
    void renew_email_sendsTheNewOfferToTheHolder() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "email", "authorization_code");

        renew(operatorToken(), id)
                .expectStatus().isOk()
                .expectBody()
                .json("{\"responses\":[{\"channel\":\"email\",\"status\":200}]}", JsonCompareMode.STRICT);

        verify(emailService).sendCredentialOfferEmail(eq(HOLDER), anyString(), anyString(), any(), isNull());
    }

    /** EC-01: with email,ui stored, one ui entry and no email. */
    @Test
    void renew_emailAndUi_isRenewedWithUiOnly() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "email,ui", "authorization_code");

        renew(operatorToken(), id)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses.length()").isEqualTo(1)
                .jsonPath("$.responses[0].channel").isEqualTo("ui")
                .jsonPath("$.responses[0].body.credential_offer_uri").exists();

        verify(emailService, never()).sendCredentialOfferEmail(anyString(), anyString(), anyString(), any(), any());
    }

    /** AC-07. */
    @Test
    void renew_tenantAdmin_renewsAnotherOrganizationsIssuance() {
        UUID id = seedIssuance(TENANT, OTHER_ORG, "DRAFT", "ui", "authorization_code");

        renew(mintUserAccessToken(TENANT, ADMIN_ORG, List.of(ONBOARDING_EXECUTE), PORTAL_CREDENTIAL_TYPE), id).expectStatus().isOk();
    }

    /** AC-10: the email link keeps working and now voids the previous offer too. */
    @Test
    void refreshLink_stillSendsANewOfferAndVoidsThePreviousOne() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "email,ui", "authorization_code");
        String previousOffer = offerUri(renew(operatorToken(), id).expectStatus().isOk());

        webTestClient().post().uri("/credential-offer/refresh/{token}", refreshToken(id))
                .header(X_TENANT_HEADER, TENANT)
                .header("X-Forwarded-For", clientIp)
                .exchange()
                .expectStatus().isOk();

        verify(emailService, atLeastOnce()).sendCredentialOfferEmail(eq(HOLDER), anyString(), anyString(), any(), isNull());
        openOffer(previousOffer).expectStatus().isEqualTo(HttpStatus.GONE);
    }

    // ── Errors: problem+json with the contract's type ─────────────────────────────────────

    /** AC-03. */
    @Test
    void renew_notDraft_is409OfferNotRenewable() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "WITHDRAWN", "ui", "authorization_code");

        expectProblem(renew(operatorToken(), id), HttpStatus.CONFLICT, "offer_not_renewable");
    }

    /** AC-04. */
    @Test
    void renew_direct_is409OfferNotRenewable() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "direct", null);

        expectProblem(renew(operatorToken(), id), HttpStatus.CONFLICT, "offer_not_renewable");
    }

    /** AC-06 / ES-02: out of scope answers exactly like nonexistent, without the id. */
    @Test
    void renew_outOfScopeAndNonexistent_areTheSame404() {
        UUID otherOrgs = seedIssuance(TENANT, OTHER_ORG, "DRAFT", "ui", "authorization_code");
        UUID unknown = UUID.randomUUID();

        JsonNode outOfScope = expectProblem(renew(operatorToken(), otherOrgs), HttpStatus.NOT_FOUND, "issuance_not_found");
        JsonNode nonexistent = expectProblem(renew(operatorToken(), unknown), HttpStatus.NOT_FOUND, "issuance_not_found");

        assertThat(outOfScope.get("detail")).isEqualTo(nonexistent.get("detail"));
        assertThat(outOfScope.toString()).doesNotContain(otherOrgs.toString());
    }

    /** EC-04: an issuance of another tenant is not found from this one. */
    @Test
    void renew_issuanceOfAnotherTenant_is404() {
        UUID id = seedIssuance(OTHER_TENANT, OPERATOR_ORG, "DRAFT", "ui", "authorization_code");

        expectProblem(renew(operatorToken(), id), HttpStatus.NOT_FOUND, "issuance_not_found");
    }

    /** AC-11: who may not issue gets 403, whether or not the issuance exists. */
    @Test
    void renew_withoutIssuingPower_is403EvenForANonexistentIssuance() {
        String viewer = mintUserAccessToken(TENANT, OPERATOR_ORG, List.of(PRODUCT_OFFERING), PORTAL_CREDENTIAL_TYPE);
        UUID own = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "ui", "authorization_code");

        expectProblem(renew(viewer, own), HttpStatus.FORBIDDEN, "insufficient_permission");
        expectProblem(renew(viewer, UUID.randomUUID()), HttpStatus.FORBIDDEN, "insufficient_permission");
    }

    /** ES-05. */
    @Test
    void renew_tokenOfAnotherTenant_is403TenantMismatch() {
        String sysAdminOfOtherTenant = mintUserAccessToken(OTHER_TENANT, ADMIN_ORG, List.of(SYSADMIN), PORTAL_CREDENTIAL_TYPE);

        expectProblem(renew(sysAdminOfOtherTenant, UUID.randomUUID()), HttpStatus.FORBIDDEN, "tenant_mismatch");
    }

    /** ES-01. */
    @Test
    void renew_idNotUuid_is400BadRequest() {
        expectProblem(renewRaw(operatorToken(), "abc"), HttpStatus.BAD_REQUEST, "BAD_REQUEST");
    }

    /** ES-03. */
    @Test
    void renew_withoutToken_is401ProblemJson() {
        webTestClient().post().uri("/api/v1/issuances/{id}/credential-offer", UUID.randomUUID())
                .header(X_TENANT_HEADER, TENANT)
                .header("X-Forwarded-For", clientIp)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON);
    }

    /** ES-06 and NFR-1: the email fails, 503 with Retry-After, and the previous offer still works. */
    @Test
    void renew_emailFails_is503AndThePreviousOfferStillWorks() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "email,ui", "authorization_code");
        String previousOffer = offerUri(renew(operatorToken(), id).expectStatus().isOk());
        databaseClient.sql("UPDATE \"" + TENANT + SCHEMA_SUFFIX + "\".issuance SET delivery = 'email' WHERE issuance_id = :id")
                .bind("id", id).then().block();
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("smtp down")));

        expectProblem(renew(operatorToken(), id), HttpStatus.SERVICE_UNAVAILABLE, "wallet_delivery_timeout");

        openOffer(previousOffer).expectStatus().isOk();
    }

    /** AC-09: past the limit, 429 rate_limited problem+json with Retry-After. */
    @Test
    void renew_overTheVolumeLimit_is429RateLimited() {
        for (int i = 0; i < RATE_LIMIT; i++) {
            renewRaw(null, "abc").expectStatus().value(status -> assertThat(status).isNotEqualTo(429));
        }

        renewRaw(null, "abc")
                .expectStatus().isEqualTo(HttpStatus.TOO_MANY_REQUESTS)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectHeader().exists(HttpHeaders.RETRY_AFTER)
                .expectBody()
                .jsonPath("$.type").isEqualTo("rate_limited")
                .jsonPath("$.status").isEqualTo(429);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private String operatorToken() {
        return mintUserAccessToken(TENANT, OPERATOR_ORG, List.of(ONBOARDING_EXECUTE), PORTAL_CREDENTIAL_TYPE);
    }

    private WebTestClient.ResponseSpec renew(String token, UUID id) {
        return renewRaw(token, id.toString());
    }

    private WebTestClient.ResponseSpec renewRaw(String token, String id) {
        WebTestClient.RequestHeadersSpec<?> request = webTestClient()
                .post().uri("/api/v1/issuances/{id}/credential-offer", id)
                .header(X_TENANT_HEADER, TENANT)
                .header("X-Forwarded-For", clientIp);
        if (token != null) {
            request = request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }
        return request.exchange();
    }

    private static JsonNode expectProblem(WebTestClient.ResponseSpec response, HttpStatus status, String type) {
        JsonNode body = response
                .expectStatus().isEqualTo(status)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody(JsonNode.class).returnResult().getResponseBody();
        assertThat(body).isNotNull();
        assertThat(body.path("type").asText()).isEqualTo(type);
        assertThat(body.path("status").asInt()).isEqualTo(status.value());
        assertThat(body.path("title").asText()).isNotBlank();
        return body;
    }

    private static String offerUri(WebTestClient.ResponseSpec response) {
        JsonNode body = response.expectBody(JsonNode.class).returnResult().getResponseBody();
        assertThat(body).isNotNull();
        return body.path("responses").path(0).path("body").path("credential_offer_uri").asText();
    }

    /** GET of the https offer URL the openid-credential-offer:// link points to. */
    private WebTestClient.ResponseSpec openOffer(String credentialOfferUri) {
        String offerUrl = URLDecoder.decode(credentialOfferUri.substring(credentialOfferUri.indexOf('=') + 1),
                StandardCharsets.UTF_8);
        String nonce = offerUrl.substring(offerUrl.lastIndexOf('/') + 1);
        return webTestClient().get().uri("/oid4vci/v1/credential-offer/{nonce}", nonce)
                .header(X_TENANT_HEADER, TENANT)
                .exchange();
    }

    private static String preAuthorizedCode(JsonNode offer) {
        assertThat(offer).isNotNull();
        return offer.path("grants").path(PRE_AUTHORIZED).path("pre-authorized_code").asText();
    }

    /** The PIN the issuer sent to the holder when the offer was opened. */
    private String lastPin() {
        ArgumentCaptor<String> pin = ArgumentCaptor.forClass(String.class);
        verify(emailService, atLeastOnce()).sendTxCodeNotification(eq(HOLDER), pin.capture());
        return pin.getValue();
    }

    private WebTestClient.ResponseSpec token(String preAuthorizedCode, String pin) {
        return webTestClient().post().uri("/oauth/token")
                .header(X_TENANT_HEADER, TENANT)
                .header("X-Forwarded-For", clientIp)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", PRE_AUTHORIZED)
                        .with("pre-authorized_code", preAuthorizedCode)
                        .with("tx_code", pin))
                .exchange();
    }

    private UUID seedIssuance(String tenant, String organization, String status, String delivery, String grantType) {
        UUID id = UUID.randomUUID();
        databaseClient.sql("INSERT INTO \"" + tenant + SCHEMA_SUFFIX + "\".issuance "
                        + "(issuance_id, credential_format, credential_data_set, credential_status, credential_type, "
                        + "organization_identifier, email, delivery, grant_type, credential_offer_refresh_token) "
                        + "VALUES (:id, 'dc+sd-jwt', '{}', :status, :type, :org, :email, :delivery, :grant, :refresh)")
                .bind("id", id)
                .bind("status", status)
                .bind("type", CONFIG_ID)
                .bind("org", organization)
                .bind("email", HOLDER)
                .bind("delivery", delivery)
                .bind("grant", grantType == null ? "authorization_code" : grantType)
                .bind("refresh", UUID.randomUUID().toString())
                .then().block();
        return id;
    }

    private String refreshToken(UUID id) {
        return databaseClient.sql("SELECT credential_offer_refresh_token FROM \"" + TENANT + SCHEMA_SUFFIX
                        + "\".issuance WHERE issuance_id = :id")
                .bind("id", id)
                .map(row -> row.get(0, String.class))
                .one().block();
    }

    private String issuanceStatus(String tenant, UUID id) {
        return databaseClient.sql("SELECT credential_status FROM \"" + tenant + SCHEMA_SUFFIX
                        + "\".issuance WHERE issuance_id = :id")
                .bind("id", id)
                .map(row -> row.get(0, String.class))
                .one().block();
    }

    private Long issuanceCount(String tenant, String organization) {
        return databaseClient.sql("SELECT count(*) FROM \"" + tenant + SCHEMA_SUFFIX
                        + "\".issuance WHERE organization_identifier = :org")
                .bind("org", organization)
                .map(row -> row.get(0, Long.class))
                .one().block();
    }

    private void seedTenantConfig(String tenant) {
        upsertConfig(tenant, "admin_organization_id", ADMIN_ORG);
        upsertConfig(tenant, "issuer.frontend_url", "https://frontend.example.com/issuer");
    }

    private void upsertConfig(String tenant, String key, String value) {
        databaseClient.sql("INSERT INTO \"" + tenant + SCHEMA_SUFFIX + "\".tenant_config (config_key, config_value) "
                        + "VALUES (:key, :value) "
                        + "ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value")
                .bind("key", key)
                .bind("value", value)
                .then().block();
    }
}
