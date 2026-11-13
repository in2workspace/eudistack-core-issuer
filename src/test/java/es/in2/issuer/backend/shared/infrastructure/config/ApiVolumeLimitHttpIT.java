package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.EntityExchangeResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The volume limits of the management APIs through the real HTTP, authentication and database path (EUD-269):
 * per person, per organization for its systems, raised per organization from the tenant configuration, on the
 * listing, the issuance (AC-08 and AC-20 of EUD-254) and the revocation (AC-09 of EUD-247). Low limits so the
 * test sends a handful of requests; the defaults of the PRDs are covered by the unit tests. The requests under
 * the limit need not succeed: every request that reaches the API is counted, and the limit is decided first.
 */
@TestPropertySource(properties = {
        "issuer.api.volume-limit.read.per-person=3",
        "issuer.api.volume-limit.read.systems-per-organization=4",
        "issuer.api.volume-limit.issuance.per-person=2",
        "issuer.api.volume-limit.revocation.per-person=2"
})
class ApiVolumeLimitHttpIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-b";

    private static String organization() {
        return "VATES-IT" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

    private EntityExchangeResult<Map<String, Object>> list(String token) {
        return webTestClient()
                .get().uri("/api/v1/issuances")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .exchange()
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult();
    }

    private EntityExchangeResult<Map<String, Object>> send(HttpMethod method, String path, String token, String body) {
        return webTestClient()
                .method(method).uri(path)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectBody(new ParameterizedTypeReference<Map<String, Object>>() {})
                .returnResult();
    }

    private String person(String organization, String email) {
        return mintUserAccessToken(TENANT, organization, List.of(Map.of("type", "domain", "domain", TENANT,
                "function", "Onboarding", "action", List.of("Execute"))), email);
    }

    /** A LEAR machine attestation of the organization, as the verifier puts it in the access token. */
    private String system(String organization, String machine) {
        long now = Instant.now().getEpochSecond();
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("iss", "http://localhost:" + port + "/issuer");
        payload.put("sub", machine);
        payload.put("iat", now);
        payload.put("exp", now + 3600);
        payload.putObject("mandator").put("organizationIdentifier", organization);
        payload.set("power", objectMapper.valueToTree(List.of(Map.of("type", "domain", "domain", TENANT,
                "function", "Onboarding", "action", List.of("Execute")))));
        payload.put("tenant", TENANT);
        payload.put("credential_type", "learcredential.machine.sd.1");
        return jwtService.issueJWT(payload.toString());
    }

    private static void assertRateLimited(EntityExchangeResult<Map<String, Object>> result) {
        assertThat(result.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(result.getResponseHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(Long.parseLong(result.getResponseHeaders().getFirst(HttpHeaders.RETRY_AFTER))).isBetween(1L, 120L);
        assertThat(result.getResponseBody()).containsEntry("type", "rate_limited").containsEntry("status", 429);
    }

    @Test
    void aPerson_overItsLimit_isRateLimited_whileAnotherPersonOfTheSameOrganizationIsNot() {
        String organization = organization();
        String ana = person(organization, "ana@example.org");

        for (int i = 0; i < 3; i++) {
            assertThat(list(ana).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }
        assertRateLimited(list(ana));
        assertThat(list(person(organization, "bea@example.org")).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void theSystemsOfAnOrganization_shareItsLimit() {
        String organization = organization();

        for (int i = 0; i < 4; i++) {
            String machine = i % 2 == 0 ? "machine-1" : "machine-2";
            assertThat(list(system(organization, machine)).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }
        assertRateLimited(list(system(organization, "machine-3")));
        // Another organization, and a person of the same one, count apart.
        assertThat(list(system(organization(), "machine-1")).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(list(person(organization, "ana@example.org")).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void supportRaisesTheLimitOfOneOrganization_fromTheTenantConfiguration() {
        String organization = organization();
        databaseClient.sql("INSERT INTO \"" + TENANT + SCHEMA_SUFFIX + "\".tenant_config (config_key, config_value) "
                        + "VALUES (:key, '6')")
                .bind("key", "issuer.volume_limit.read." + organization)
                .then().block();

        for (int i = 0; i < 6; i++) {
            assertThat(list(system(organization, "machine-1")).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }
        assertRateLimited(list(system(organization, "machine-1")));
    }

    @Test
    void theIssuanceOfAPerson_overItsLimit_isRateLimited_againstTheSharedCounters() {
        String ana = person(organization(), "ana@example.org");
        // An invalid request is still counted: the limit is decided before anything else.
        String body = "{}";

        for (int i = 0; i < 2; i++) {
            assertThat(send(HttpMethod.POST, "/api/v1/issuances", ana, body).getStatus())
                    .isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }
        assertRateLimited(send(HttpMethod.POST, "/api/v1/issuances", ana, body));
        // The renewal of a credential offer counts as an issuance too (EUD-295).
        assertRateLimited(send(HttpMethod.POST, "/api/v1/issuances/" + UUID.randomUUID() + "/credential-offer", ana, body));
    }

    @Test
    void theRevocationsOfAPerson_byEitherRoute_shareItsLimit() {
        String ana = person(organization(), "ana@example.org");
        String revocation = "/api/v1/issuances/" + UUID.randomUUID() + "/revocation";
        String patch = "/api/v1/issuances/" + UUID.randomUUID();

        assertThat(send(HttpMethod.POST, revocation, ana, "{\"reason\":\"x\"}").getStatus())
                .isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(send(HttpMethod.PATCH, patch, ana, "{\"status\":\"REVOKED\"}").getStatus())
                .isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertRateLimited(send(HttpMethod.POST, revocation, ana, "{\"reason\":\"x\"}"));
        assertRateLimited(send(HttpMethod.PATCH, patch, ana, "{\"status\":\"REVOKED\"}"));
        // The listing has its own count.
        assertThat(list(ana).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }
}
