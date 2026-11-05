package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.oidc4vci.domain.model.ActiveCredentialOffer;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferData;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

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
    // Powers as the action matrix of EUD-272 recognizes them: the tenant administrator by
    // organization · <tenant> · Onboarding · Execute, an organization administrator by domain · <tenant> · ...
    private static final Map<String, Object> TENANT_ADMIN =
            Map.of("type", "organization", "domain", TENANT, "function", "Onboarding", "action", List.of("Execute"));
    private static final Map<String, Object> ORG_ADMIN =
            Map.of("type", "domain", "domain", TENANT, "function", "Onboarding", "action", List.of("Execute"));
    private static final Map<String, Object> ORG_ADMIN_OF_ANOTHER_DOMAIN =
            Map.of("type", "domain", "domain", "DOME", "function", "Onboarding", "action", List.of("Execute"));
    private static final Map<String, Object> CERTIFY =
            Map.of("type", "domain", "domain", TENANT, "function", "Certification", "action", List.of("Attest"));
    private static final Map<String, Object> PRODUCT_OFFERING =
            Map.of("type", "domain", "domain", TENANT, "function", "ProductOffering", "action", List.of("Create"));
    private static final Map<String, Object> SYSADMIN =
            Map.of("type", "organization", "domain", "EUDISTACK", "function", "System", "action", List.of("Administration"));

    @MockitoBean
    private EmailService emailService;

    @Autowired
    private TransientStore<ActiveCredentialOffer> activeCredentialOfferStore;

    @Autowired
    private TransientStore<CredentialOfferData> credentialOfferStore;

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

    /**
     * AC-01 and AC-05: a new offer with a new pre-authorized code; the previous offer and code no
     * longer work. The previous offer is never opened before the renewal, so its 410 can only come
     * from the renewal voiding it.
     */
    @Test
    void renew_ui_returnsANewOfferAndVoidsThePreviousOneWithItsCode() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "ui", PRE_AUTHORIZED);
        String operator = operatorToken();
        long issuancesBefore = issuanceCount(TENANT, OPERATOR_ORG);

        String firstOffer = offerUri(renew(operator, id).expectStatus().isOk());
        ActiveCredentialOffer first = activeOffer(id);
        String firstCode = first.preAuthorizedCode();
        String firstPin = storedOffer(first.nonce()).txCode();
        assertThat(firstCode).isNotBlank();

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

    /** EC-05: the wallet already opened the previous offer without collecting the attestation. */
    @Test
    void renew_previousOfferAlreadyOpened_isRenewed() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "ui", PRE_AUTHORIZED);
        String previousOffer = offerUri(renew(operatorToken(), id).expectStatus().isOk());
        openOffer(previousOffer).expectStatus().isOk();

        String newOffer = offerUri(renew(operatorToken(), id).expectStatus().isOk());

        JsonNode opened = openOffer(newOffer).expectStatus().isOk().expectBody(JsonNode.class).returnResult().getResponseBody();
        token(preAuthorizedCode(opened), lastPin()).expectStatus().isOk();
    }

    /** EC-03: the previous offer expired long ago; the new one is served for 10 minutes. */
    @Test
    void renew_previousOfferExpired_isRenewedWithATenMinuteOffer() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "ui", PRE_AUTHORIZED);
        String previousOffer = offerUri(renew(operatorToken(), id).expectStatus().isOk());
        String previousNonce = activeOffer(id).nonce();
        CredentialOfferData previous = storedOffer(previousNonce);
        credentialOfferStore.add(previousNonce,
                previous.toBuilder().expiresAt(Instant.now().minus(Duration.ofMinutes(11))).build()).block();
        openOffer(previousOffer).expectStatus().isEqualTo(HttpStatus.GONE);

        Instant renewedAt = Instant.now();
        String newOffer = offerUri(renew(operatorToken(), id).expectStatus().isOk());

        assertThat(storedOffer(activeOffer(id).nonce()).expiresAt())
                .isBetween(renewedAt.plus(Duration.ofMinutes(10)).minusSeconds(5),
                        Instant.now().plus(Duration.ofMinutes(10)));
        openOffer(newOffer).expectStatus().isOk();
    }

    /** EC-02: renewals at the same time; at most one new offer works, never the one before them. */
    @Test
    void renew_concurrently_leavesAtMostOneNewOfferUsable() throws Exception {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "ui", PRE_AUTHORIZED);
        String operator = operatorToken();
        String original = offerUri(renew(operator, id).expectStatus().isOk());

        int renewals = 6;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(renewals);
        try {
            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < renewals; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return offerUri(renew(operator, id).expectStatus().isOk());
                }));
            }
            start.countDown();
            List<String> newOffers = new ArrayList<>();
            for (Future<String> future : futures) {
                newOffers.add(future.get(30, TimeUnit.SECONDS));
            }

            assertThat(newOffers).doesNotHaveDuplicates().doesNotContain(original);
            openOffer(original).expectStatus().isEqualTo(HttpStatus.GONE);
            long usable = newOffers.stream()
                    .filter(offer -> openOffer(offer).expectBody().returnResult().getStatus().value() == 200)
                    .count();
            assertThat(usable).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
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

        renew(tenantAdminToken(), id).expectStatus().isOk();
    }

    /**
     * AC-10: the email link keeps working and now voids the previous offer too. EC-02 in both
     * orders: API then link, and link then API.
     */
    @Test
    void refreshLink_stillSendsANewOfferAndVoidsThePreviousOne() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "email,ui", "authorization_code");
        String previousOffer = offerUri(renew(operatorToken(), id).expectStatus().isOk());

        webTestClient().post().uri("/credential-offer/refresh/{token}", refreshToken(id))
                .header(X_TENANT_HEADER, TENANT)
                .header("X-Forwarded-For", clientIp)
                .exchange()
                .expectStatus().isOk();

        ArgumentCaptor<String> sent = ArgumentCaptor.forClass(String.class);
        verify(emailService, atLeastOnce()).sendCredentialOfferEmail(eq(HOLDER), sent.capture(), anyString(), any(), isNull());
        String linkOffer = sent.getValue();
        openOffer(previousOffer).expectStatus().isEqualTo(HttpStatus.GONE);

        String apiOffer = offerUri(renew(operatorToken(), id).expectStatus().isOk());

        openOffer(linkOffer).expectStatus().isEqualTo(HttpStatus.GONE);
        openOffer(apiOffer).expectStatus().isOk();
        assertThat(issuanceStatus(TENANT, id)).isEqualTo("DRAFT");
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

    /** AC-06 / ES-02 / NFR-1: out of scope answers exactly like nonexistent, without the id, and B's offer still works. */
    @Test
    void renew_outOfScopeAndNonexistent_areTheSame404() {
        UUID otherOrgs = seedIssuance(TENANT, OTHER_ORG, "DRAFT", "ui", "authorization_code");
        String otherOrgsOffer = offerUri(renew(tenantAdminToken(), otherOrgs).expectStatus().isOk());
        UUID unknown = UUID.randomUUID();

        JsonNode outOfScope = expectProblem(renew(operatorToken(), otherOrgs), HttpStatus.NOT_FOUND, "issuance_not_found");
        JsonNode nonexistent = expectProblem(renew(operatorToken(), unknown), HttpStatus.NOT_FOUND, "issuance_not_found");

        assertThat(outOfScope.get("detail")).isEqualTo(nonexistent.get("detail"));
        assertThat(outOfScope.toString()).doesNotContain(otherOrgs.toString());
        openOffer(otherOrgsOffer).expectStatus().isOk();
    }

    /** EC-04: an issuance of another tenant is not found from this one. */
    @Test
    void renew_issuanceOfAnotherTenant_is404() {
        UUID id = seedIssuance(OTHER_TENANT, OPERATOR_ORG, "DRAFT", "ui", "authorization_code");

        expectProblem(renew(operatorToken(), id), HttpStatus.NOT_FOUND, "issuance_not_found");
    }

    /** AC-11 / NFR-1: who may not issue gets 403, whether or not the issuance exists, and the offer still works. */
    @Test
    void renew_withoutIssuingPower_is403EvenForANonexistentIssuance() {
        String viewer = mintUserAccessToken(TENANT, OPERATOR_ORG, List.of(PRODUCT_OFFERING));
        UUID own = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "ui", "authorization_code");
        UUID otherOrgs = seedIssuance(TENANT, OTHER_ORG, "DRAFT", "ui", "authorization_code");
        String ownOffer = offerUri(renew(operatorToken(), own).expectStatus().isOk());

        expectProblem(renew(viewer, own), HttpStatus.FORBIDDEN, "insufficient_permission");
        expectProblem(renew(viewer, UUID.randomUUID()), HttpStatus.FORBIDDEN, "insufficient_permission");
        expectProblem(renew(viewer, otherOrgs), HttpStatus.FORBIDDEN, "insufficient_permission");

        openOffer(ownOffer).expectStatus().isOk();
    }

    /**
     * Who may renew is who may issue (E1/E2): Certification · Attest only issues product
     * certifications (E6), and a power of another domain is no power in this tenant (review S1).
     */
    @Test
    void renew_onlyCertificationAttestOrAPowerOfAnotherDomain_is403AndTheOfferStillWorks() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "ui", "authorization_code");
        String offer = offerUri(renew(operatorToken(), id).expectStatus().isOk());

        expectProblem(renew(mintUserAccessToken(TENANT, OPERATOR_ORG, List.of(CERTIFY)), id),
                HttpStatus.FORBIDDEN, "insufficient_permission");
        expectProblem(renew(mintUserAccessToken(TENANT, OPERATOR_ORG, List.of(ORG_ADMIN_OF_ANOTHER_DOMAIN)), id),
                HttpStatus.FORBIDDEN, "insufficient_permission");

        openOffer(offer).expectStatus().isOk();
    }

    /** ES-05. */
    @Test
    void renew_tokenOfAnotherTenant_is403TenantMismatch() {
        String sysAdminOfOtherTenant = mintUserAccessToken(OTHER_TENANT, ADMIN_ORG, List.of(SYSADMIN));

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

    /** ES-03: a token whose signature does not verify. */
    @Test
    void renew_badlySignedToken_is401ProblemJson() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "ui", "authorization_code");
        String valid = operatorToken();
        byte[] otherSignature = new byte[64];
        ThreadLocalRandom.current().nextBytes(otherSignature);
        String forged = valid.substring(0, valid.lastIndexOf('.') + 1)
                + Base64.getUrlEncoder().withoutPadding().encodeToString(otherSignature);

        expectUnauthorized(renew(forged, id));
    }

    /**
     * ES-06 and NFR-1: the email fails, 503 with Retry-After; the previous offer still works and
     * the offer created for the failed attempt does not.
     */
    @Test
    void renew_emailFails_is503AndThePreviousOfferStillWorks() {
        UUID id = seedIssuance(TENANT, OPERATOR_ORG, "DRAFT", "email,ui", "authorization_code");
        String previousOffer = offerUri(renew(operatorToken(), id).expectStatus().isOk());
        databaseClient.sql("UPDATE \"" + TENANT + SCHEMA_SUFFIX + "\".issuance SET delivery = 'email' WHERE issuance_id = :id")
                .bind("id", id).then().block();
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("smtp down")));

        WebTestClient.ResponseSpec failed = renew(operatorToken(), id);
        failed.expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "30");
        expectProblem(failed, HttpStatus.SERVICE_UNAVAILABLE, "wallet_delivery_timeout");

        ArgumentCaptor<String> attempted = ArgumentCaptor.forClass(String.class);
        verify(emailService, atLeastOnce()).sendCredentialOfferEmail(eq(HOLDER), attempted.capture(), anyString(), any(), isNull());
        String failedAttemptOffer = attempted.getValue();
        assertThat(failedAttemptOffer).isNotEqualTo(previousOffer);
        openOffer(failedAttemptOffer).expectStatus().isEqualTo(HttpStatus.GONE);
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
        return mintUserAccessToken(TENANT, OPERATOR_ORG, List.of(ORG_ADMIN));
    }

    private String tenantAdminToken() {
        return mintUserAccessToken(TENANT, ADMIN_ORG, List.of(TENANT_ADMIN));
    }

    private static void expectUnauthorized(WebTestClient.ResponseSpec response) {
        JsonNode body = response
                .expectStatus().isUnauthorized()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody(JsonNode.class).returnResult().getResponseBody();
        assertThat(body).isNotNull();
        assertThat(body.path("type").asText()).isIn("invalid_token", "authentication_error");
        assertThat(body.path("status").asInt()).isEqualTo(401);
    }

    /** The issuance's current offer, as the in-memory index holds it. */
    private ActiveCredentialOffer activeOffer(UUID id) {
        ActiveCredentialOffer offer = activeCredentialOfferStore.get(id.toString()).block();
        assertThat(offer).isNotNull();
        return offer;
    }

    /** An offer as stored under its nonce, read without redeeming it. */
    private CredentialOfferData storedOffer(String nonce) {
        CredentialOfferData offer = credentialOfferStore.get(nonce).block();
        assertThat(offer).isNotNull();
        return offer;
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
