package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.OID4VCI_AUTHORIZE_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;

/**
 * EUD-295 AC-05, second scenario: renewing the offer of an {@code authorization_code} issuance
 * voids the previous {@code issuer_state}. A code obtained with it, before or after the renewal,
 * gets no token; the new offer's {@code issuer_state} does.
 *
 * <p>The wallet's own authentication is switched off here -- PAR, DPoP and the client attestation
 * (WIA) -- because none of them takes part in the {@code issuer_state} check, which is the only
 * thing under test, and a WIA cannot be minted in this IT. PKCE stays on, as in production. The
 * {@code issuer_state} is resolved at {@code /oauth/token} ({@code TokenServiceImpl}); PAR and
 * authorize only carry it, so that is where both old codes fail.
 */
@TestPropertySource(properties = {
        "oid4vci.profile.authorization-code.require-par=false",
        "oid4vci.profile.authorization-code.require-dpop=false",
        "oid4vci.profile.authorization-code.client-auth-method=none"
})
class CredentialOfferRenewalAuthCodeIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-a";
    private static final String ADMIN_ORG = "admin-org-for-renewal-auth-code-it";
    private static final String OPERATOR_ORG = "operator-org-for-renewal-auth-code-it";
    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String AUTHORIZATION_CODE = "authorization_code";
    private static final String CLIENT_ID = "https://wallet.example/it";
    private static final String REDIRECT_URI = "https://wallet.example/callback";

    private static final Map<String, Object> ONBOARDING_EXECUTE =
            Map.of("type", "domain", "domain", "DOME", "function", "Onboarding", "action", List.of("Execute"));

    @MockitoBean
    private EmailService emailService;

    private String clientIp;

    @BeforeEach
    void setUp() {
        clientIp = "10.%d.%d.%d".formatted(ThreadLocalRandom.current().nextInt(1, 255),
                ThreadLocalRandom.current().nextInt(1, 255), ThreadLocalRandom.current().nextInt(1, 255));
        upsertConfig("admin_organization_id", ADMIN_ORG);
        upsertConfig("issuer.frontend_url", "https://frontend.example.com/issuer");
        lenient().when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(Mono.empty());
    }

    @Test
    void renew_authorizationCode_voidsThePreviousIssuerStateAndTheNewOneGetsAToken() {
        UUID id = seedDraftIssuance();
        String operator = mintUserAccessToken(TENANT, OPERATOR_ORG, List.of(ONBOARDING_EXECUTE), CONFIG_ID);

        String previousState = issuerState(openOffer(renew(operator, id)));
        // The wallet started with the previous offer before the renewal...
        String verifier = codeVerifier();
        String codeBeforeRenewal = authorize(previousState, verifier);

        String newState = issuerState(openOffer(renew(operator, id)));
        assertThat(newState).isNotBlank().isNotEqualTo(previousState);

        // ...so its code fails at token, and so does a code obtained with the old state afterwards.
        expectInvalidGrant(token(codeBeforeRenewal, verifier));
        String codeAfterRenewal = authorize(previousState, verifier);
        expectInvalidGrant(token(codeAfterRenewal, verifier));

        // The new offer goes through.
        String newVerifier = codeVerifier();
        token(authorize(newState, newVerifier), newVerifier)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.access_token").isNotEmpty();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private String renew(String token, UUID id) {
        JsonNode body = webTestClient().post().uri("/api/v1/issuances/{id}/credential-offer", id)
                .header(X_TENANT_HEADER, TENANT)
                .header("X-Forwarded-For", clientIp)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(JsonNode.class).returnResult().getResponseBody();
        assertThat(body).isNotNull();
        return body.path("responses").path(0).path("body").path("credential_offer_uri").asText();
    }

    private JsonNode openOffer(String credentialOfferUri) {
        String offerUrl = URLDecoder.decode(credentialOfferUri.substring(credentialOfferUri.indexOf('=') + 1),
                StandardCharsets.UTF_8);
        String nonce = offerUrl.substring(offerUrl.lastIndexOf('/') + 1);
        return webTestClient().get().uri("/oid4vci/v1/credential-offer/{nonce}", nonce)
                .header(X_TENANT_HEADER, TENANT)
                .exchange()
                .expectStatus().isOk()
                .expectBody(JsonNode.class).returnResult().getResponseBody();
    }

    private static String issuerState(JsonNode offer) {
        assertThat(offer).isNotNull();
        return offer.path("grants").path(AUTHORIZATION_CODE).path("issuer_state").asText();
    }

    /** Direct authorization request (PAR off); returns the code from the redirect. */
    private String authorize(String issuerState, String verifier) {
        URI location = webTestClient().get()
                .uri(builder -> builder.path(OID4VCI_AUTHORIZE_PATH)
                        .queryParam("response_type", "code")
                        .queryParam("client_id", CLIENT_ID)
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("code_challenge", codeChallenge(verifier))
                        .queryParam("code_challenge_method", "S256")
                        .queryParam("issuer_state", issuerState)
                        .build())
                .header(X_TENANT_HEADER, TENANT)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.FOUND)
                .returnResult(Void.class).getResponseHeaders().getLocation();
        assertThat(location).isNotNull();
        String code = UriComponentsBuilder.fromUri(location).build().getQueryParams().getFirst("code");
        assertThat(code).isNotBlank();
        return URLDecoder.decode(code, StandardCharsets.UTF_8);
    }

    private WebTestClient.ResponseSpec token(String code, String verifier) {
        return webTestClient().post().uri("/oauth/token")
                .header(X_TENANT_HEADER, TENANT)
                .header("X-Forwarded-For", clientIp)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", AUTHORIZATION_CODE)
                        .with("code", code)
                        .with("redirect_uri", REDIRECT_URI)
                        .with("code_verifier", verifier))
                .exchange();
    }

    private static void expectInvalidGrant(WebTestClient.ResponseSpec response) {
        response.expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("invalid_grant");
    }

    private static String codeVerifier() {
        byte[] bytes = new byte[32];
        ThreadLocalRandom.current().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String codeChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private UUID seedDraftIssuance() {
        UUID id = UUID.randomUUID();
        databaseClient.sql("INSERT INTO \"" + TENANT + SCHEMA_SUFFIX + "\".issuance "
                        + "(issuance_id, credential_format, credential_data_set, credential_status, credential_type, "
                        + "organization_identifier, email, delivery, grant_type, credential_offer_refresh_token) "
                        + "VALUES (:id, 'dc+sd-jwt', '{}', 'DRAFT', :type, :org, 'holder@example.com', 'ui', "
                        + "'authorization_code', :refresh)")
                .bind("id", id)
                .bind("type", CONFIG_ID)
                .bind("org", OPERATOR_ORG)
                .bind("refresh", UUID.randomUUID().toString())
                .then().block();
        return id;
    }

    private void upsertConfig(String key, String value) {
        databaseClient.sql("INSERT INTO \"" + TENANT + SCHEMA_SUFFIX + "\".tenant_config (config_key, config_value) "
                        + "VALUES (:key, :value) "
                        + "ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value")
                .bind("key", key)
                .bind("value", value)
                .then().block();
    }
}
