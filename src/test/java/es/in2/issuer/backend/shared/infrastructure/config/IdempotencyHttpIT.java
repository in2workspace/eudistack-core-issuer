package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.IssuerApiApplication;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * AC-07 of the idempotency (EUD-269, FR-08 of EUD-254) through the real chain: HTTP, authentication, tenant,
 * {@link IdempotencyFilter}, the encryption of the kept response and the store in the tenant's schema. Only the
 * issuance itself is a fake -- it decides with the real decision point and counts the processes it creates --
 * since creating a real process needs the QTSP, the mail server and the credential catalogue.
 *
 * <p>"Another instance" and "after a restart" are a second application context on the same database, started
 * after the first request was kept: nothing of the first instance's memory reaches it.
 */
class IdempotencyHttpIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-b";
    private static final String OTHER_TENANT = "e2e-tenant-a";
    private static final String EMAIL = "ana@example.org";

    @MockitoBean
    private IssuanceWorkflow issuanceWorkflow;

    @Autowired
    private PowerAuthorizationService powerAuthorizationService;

    private final AtomicInteger processes = new AtomicInteger();

    @BeforeEach
    void issuanceDecidesWithTheRealDecisionPoint_andCountsItsProcesses() {
        processes.set(0);
        when(issuanceWorkflow.issueCredential(anyString(), any(), anyString(), anyString())).thenAnswer(invocation ->
                powerAuthorizationService.authorizeQuery(null, null)
                        .map(decision -> IssuanceResponse.builder()
                                .signedCredential("eyJ.signed." + processes.incrementAndGet())
                                .deliveryResults(List.of(DeliveryResult.delivered("direct")))
                                .issuanceId(UUID.randomUUID().toString())
                                .build()));
    }

    private static String organization() {
        return "VATES-IT" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

    private static String body(String email) {
        return "{\"credential_configuration_id\":\"learcredential.employee.sd.1\",\"delivery\":\"direct\","
                + "\"email\":\"" + email + "\",\"payload\":{\"mandatee\":{\"email\":\"" + email + "\"}}}";
    }

    /** An operator of the organization, in the tenant {@code tokenTenant}, as {@code issuerPort} signs it. */
    private static String operator(JWTService signer, int issuerPort, String tokenTenant, String organization) {
        long now = Instant.now().getEpochSecond();
        ObjectNode payload = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
        payload.put("iss", "http://localhost:" + issuerPort + "/issuer");
        payload.put("sub", "it-user-" + organization);
        payload.put("iat", now);
        payload.put("exp", now + 3600);
        payload.putObject("mandator").put("organizationIdentifier", organization);
        payload.set("power", new com.fasterxml.jackson.databind.ObjectMapper().valueToTree(List.of(Map.of(
                "type", "domain", "domain", tokenTenant, "function", "Onboarding", "action", List.of("Execute")))));
        payload.put("tenant", tokenTenant);
        payload.putObject("vc").putObject("credentialSubject").putObject("mandate").putObject("mandatee")
                .put("email", EMAIL);
        return signer.issueJWT(payload.toString());
    }

    private static EntityExchangeResult<byte[]> issue(WebTestClient client, String token, String tenant, String key,
                                                      String body) {
        return client.post().uri("/api/v1/issuances")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, tenant)
                .header(IdempotencyFilter.IDEMPOTENCY_HEADER, key)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectBody()
                .returnResult();
    }

    private static String text(EntityExchangeResult<byte[]> result) {
        return result.getResponseBody() == null ? "" : new String(result.getResponseBody(), StandardCharsets.UTF_8);
    }

    private long keptRecords() {
        return databaseClient.sql("SELECT count(*) AS n FROM \"" + TENANT + SCHEMA_SUFFIX + "\".api_idempotency_record "
                        + "WHERE state = 'COMPLETED' AND encode(response_body, 'escape') LIKE '%eyJ.signed%'")
                .map((row, metadata) -> row.get("n", Long.class))
                .one()
                .block();
    }

    @Test
    void sameKeyAndBody_getsTheSameResponse_withOneProcess_andAnotherBody_is422() {
        String token = operator(jwtService, port, TENANT, organization());
        String key = "it-" + UUID.randomUUID();

        EntityExchangeResult<byte[]> first = issue(webTestClient(), token, TENANT, key, body(EMAIL));
        EntityExchangeResult<byte[]> second = issue(webTestClient(), token, TENANT, key,
                // The same request serialized another way is the same body.
                body(EMAIL).replace(",", " , "));
        EntityExchangeResult<byte[]> reused = issue(webTestClient(), token, TENANT, key, body("bea@example.org"));

        assertThat(first.getStatus()).isEqualTo(HttpStatus.OK);
        assertThat(text(first)).contains("eyJ.signed.1");
        assertThat(second.getStatus()).isEqualTo(HttpStatus.OK);
        assertThat(text(second)).isEqualTo(text(first));
        assertThat(second.getResponseHeaders().getLocation()).isEqualTo(first.getResponseHeaders().getLocation())
                .isNotNull();
        assertThat(second.getResponseHeaders().getContentType()).isEqualTo(first.getResponseHeaders().getContentType());
        assertThat(processes).hasValue(1);
        assertThat(reused.getStatus()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(text(reused)).contains("idempotency_key_reused");
        assertThat(processes).hasValue(1);
        // Kept in the tenant's schema, and never in clear.
        assertThat(keptRecords()).isZero();
    }

    @Test
    void aTokenOfAnotherTenant_neverGetsTheKeptResponse_andIsDeniedByTheDecisionPoint() {
        String organization = organization();
        String key = "it-" + UUID.randomUUID();
        EntityExchangeResult<byte[]> kept = issue(webTestClient(), operator(jwtService, port, TENANT, organization),
                TENANT, key, body(EMAIL));
        assertThat(kept.getStatus()).isEqualTo(HttpStatus.OK);

        // Same organization, same person, same key and body: only the tenant of the token differs.
        EntityExchangeResult<byte[]> crossTenant = issue(webTestClient(),
                operator(jwtService, port, OTHER_TENANT, organization), TENANT, key, body(EMAIL));

        assertThat(crossTenant.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(text(crossTenant)).doesNotContain("eyJ.signed");
        assertThat(processes).hasValue(1);
    }

    @Test
    void theKeptResponse_isReturnedByAnotherInstance_startedAfterwards_withoutCreatingAnotherProcess() {
        String organization = organization();
        String key = "it-" + UUID.randomUUID();
        EntityExchangeResult<byte[]> first = issue(webTestClient(), operator(jwtService, port, TENANT, organization),
                TENANT, key, body(EMAIL));
        assertThat(first.getStatus()).isEqualTo(HttpStatus.OK);

        try (ConfigurableApplicationContext otherInstance = new SpringApplicationBuilder(IssuerApiApplication.class)
                .web(WebApplicationType.REACTIVE)
                // Arguments, not default properties: the application's own configuration would override those.
                .run("--server.port=0",
                        "--spring.r2dbc.url=" + postgresR2dbcUrl(),
                        "--spring.r2dbc.username=" + postgresUsername(),
                        "--spring.r2dbc.password=" + postgresPassword(),
                        "--spring.flyway.url=" + postgresJdbcUrl())) {
            int otherPort = ((WebServerApplicationContext) otherInstance).getWebServer().getPort();
            WebTestClient otherClient = WebTestClient.bindToServer()
                    .baseUrl("http://localhost:" + otherPort + "/issuer")
                    .responseTimeout(Duration.ofSeconds(10))
                    .build();
            String token = operator(otherInstance.getBean(JWTService.class), otherPort, TENANT, organization);

            EntityExchangeResult<byte[]> replayed = issue(otherClient, token, TENANT, key, body(EMAIL));

            // The other instance has the real issuance: had it processed the request, it could not answer this.
            assertThat(replayed.getStatus()).isEqualTo(HttpStatus.OK);
            assertThat(text(replayed)).isEqualTo(text(first));
            assertThat(replayed.getResponseHeaders().getLocation()).isEqualTo(first.getResponseHeaders().getLocation());
        }
        assertThat(processes).hasValue(1);
    }
}
