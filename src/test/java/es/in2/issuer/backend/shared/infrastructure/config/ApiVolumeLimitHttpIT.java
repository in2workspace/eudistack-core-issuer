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
 * listing, the detail and the search (AC-11 of EUD-255), the issuance (AC-08 and AC-20 of EUD-254) and the revocation
 * (AC-09 of EUD-247). Low limits so the test sends a handful of requests, but for the search, which has the deployed
 * ones (EUD-270 task 8); that they are the ones of application.yml is checked by DeployedVolumeLimitsTest. The requests under
 * the limit need not succeed: every request that reaches the API is counted, and the limit is decided first.
 */
@TestPropertySource(properties = {
        "issuer.api.volume-limit.read.per-person=3",
        "issuer.api.volume-limit.read.systems-per-organization=4",
        "issuer.api.volume-limit.issuance.per-person=2",
        "issuer.api.volume-limit.revocation.per-person=2",
        "issuer.api.volume-limit.search.per-person=" + ApiVolumeLimitHttpIT.SEARCHES_PER_PERSON,
        "issuer.api.volume-limit.search.systems-per-organization=" + ApiVolumeLimitHttpIT.SEARCHES_PER_ORGANIZATION_SYSTEMS
})
class ApiVolumeLimitHttpIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-b";
    /** The deployed limits of the search (application.yml). */
    static final int SEARCHES_PER_PERSON = 10;
    static final int SEARCHES_PER_ORGANIZATION_SYSTEMS = 60;

    private static final String SEARCH = "/api/v1/issuances/search";

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

    /** A request from its own address, so the per-address counter of one test does not reach the others. */
    private EntityExchangeResult<Map<String, Object>> sendFrom(String address, HttpMethod method, String path,
                                                              String token) {
        return webTestClient()
                .method(method).uri(path)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .header("X-Forwarded-For", address)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"x\"}")
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

    /** EUD-255 AC-11: the listing and the detail are one class, read, and count together. */
    @Test
    void theListingAndTheDetailOfAPerson_shareTheReadLimit() {
        String ana = person(organization(), "ana@example.org");

        assertThat(list(ana).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(send(HttpMethod.GET, "/api/v1/issuances/" + UUID.randomUUID(), ana, "{}").getStatus())
                .isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(list(ana).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertRateLimited(send(HttpMethod.GET, "/api/v1/issuances/" + UUID.randomUUID(), ana, "{}"));
        assertRateLimited(list(ana));
    }

    /**
     * EUD-255 AC-11, ES-07 with the deployed limit: 10 searches a minute per person, counted before the shape of
     * the body (API-10), and apart from the listing.
     */
    @Test
    void theSearchOfAPerson_hasItsOwnLimit_countedBeforeTheShape() {
        String ana = person(organization(), "ana@example.org");

        for (int i = 0; i < SEARCHES_PER_PERSON; i++) {
            assertThat(send(HttpMethod.POST, SEARCH, ana, "{\"subject\": \"garcia\"}").getStatus())
                    .as("search %d", i + 1).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }
        assertRateLimited(send(HttpMethod.POST, SEARCH, ana, "{\"subject\": \"garcia\"}"));
        // Over the limit, a body that is not valid is refused for the volume, not for its shape.
        assertRateLimited(send(HttpMethod.POST, SEARCH, ana, "{\"subject\": \"ma\"}"));
        assertThat(list(ana).getStatus()).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    /** EUD-255 AC-11 with the deployed limit: the systems of an organization share 60 searches a minute. */
    @Test
    void theSystemsOfAnOrganization_shareTheirSearchLimit() {
        String organization = organization();

        for (int i = 0; i < SEARCHES_PER_ORGANIZATION_SYSTEMS; i++) {
            assertThat(send(HttpMethod.POST, SEARCH, system(organization, "machine-" + (i % 3)), "{\"subject\": \"garcia\"}")
                    .getStatus()).as("search %d", i + 1).isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }
        assertRateLimited(send(HttpMethod.POST, SEARCH, system(organization, "machine-9"), "{\"subject\": \"garcia\"}"));
        assertThat(send(HttpMethod.POST, SEARCH, system(organization(), "machine-0"), "{\"subject\": \"garcia\"}").getStatus())
                .isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
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

    /**
     * A valid token issued for another tenant than {@code X-Tenant} has no requester, so its own limit does not
     * count it: the per-address limit does (100 per minute), and the decision point is not reached any more.
     */
    @Test
    void aValidTokenOfAnotherTenant_isLimitedByAddress_after100Requests() {
        String otherTenantToken = mintUserAccessToken("e2e-other-tenant", organization(), List.of(Map.of(
                "type", "domain", "domain", TENANT, "function", "Onboarding", "action", List.of("Execute"))),
                "ana@example.org");
        String revocation = "/api/v1/issuances/" + UUID.randomUUID() + "/revocation";

        for (int i = 0; i < 100; i++) {
            assertThat(sendFrom("198.51.100.10", HttpMethod.POST, revocation, otherTenantToken).getStatus())
                    .isEqualTo(HttpStatus.FORBIDDEN);
        }
        assertThat(sendFrom("198.51.100.10", HttpMethod.POST, revocation, otherTenantToken).getStatus())
                .isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    /** A route of the management APIs with no operation is not counted by its requester: the address limit is. */
    @Test
    void aRouteWithoutOperation_isLimitedByAddress_after100Requests() {
        String ana = person(organization(), "ana@example.org");
        String path = "/api/v1/issuances/" + UUID.randomUUID();

        for (int i = 0; i < 100; i++) {
            assertThat(sendFrom("198.51.100.11", HttpMethod.PUT, path, ana).getStatus())
                    .isNotEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }
        assertThat(sendFrom("198.51.100.11", HttpMethod.PUT, path, ana).getStatus())
                .isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }
}
