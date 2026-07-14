package es.in2.issuer.backend.apiclient.infrastructure.it;

import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpHeaders;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.INTAKE_BASE_PATH;

/**
 * End-to-end coverage of the {@link es.in2.issuer.backend.apiclient.infrastructure.security.IntakeCallerAuthorizationFilter}
 * gate in front of {@code /api/v1/intake} (EUD-75, US-02).
 *
 * <p>EUD-74 (the intake endpoint itself) is not implemented yet, so a request
 * that clears the gate has nowhere to land: WebFlux routing responds 404
 * (no handler), which — for these tests — is the observable proof that the
 * gate let the request through rather than rejecting it with 401/403.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IntakeAuthenticationGateIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";
    private static final String AUTHORIZED_CLIENT_ID = "gate-authorized-client";
    private static final String AUTHORIZED_CLIENT_SECRET = "s3cr3t-authorized-pw";
    private static final String UNAUTHORIZED_CLIENT_ID = "gate-unauthorized-client";
    private static final String UNAUTHORIZED_CLIENT_SECRET = "s3cr3t-unauthorized-pw";

    @BeforeAll
    void seedApiClients() {
        seedApiClient(TENANT, AUTHORIZED_CLIENT_ID, AUTHORIZED_CLIENT_SECRET, true, "ACTIVE").block();
        seedApiClient(TENANT, UNAUTHORIZED_CLIENT_ID, UNAUTHORIZED_CLIENT_SECRET, false, "ACTIVE").block();
    }

    @Test
    void intake_noAuthorizationHeader_returnsUnauthorized() {
        webTestClient()
                .post().uri(INTAKE_BASE_PATH)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void intake_m2mTokenWithIssuanceRights_clearsGate() {
        String accessToken = acquireAccessToken(TENANT, AUTHORIZED_CLIENT_ID, AUTHORIZED_CLIENT_SECRET);

        webTestClient()
                .post().uri(INTAKE_BASE_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .exchange()
                // No EUD-74 controller exists yet: 404 proves the gate did not
                // reject the request itself (no 401/403).
                .expectStatus().isNotFound();
    }

    @Test
    void intake_m2mTokenWithoutIssuanceRights_returnsForbidden() {
        String accessToken = acquireAccessToken(TENANT, UNAUTHORIZED_CLIENT_ID, UNAUTHORIZED_CLIENT_SECRET);

        webTestClient()
                .post().uri(INTAKE_BASE_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .exchange()
                .expectStatus().isForbidden();
    }

    private String acquireAccessToken(String tenant, String clientId, String clientSecret) {
        TokenResponse response = requestToken(tenant, clientId, clientSecret)
                .expectStatus().isOk()
                .expectBody(TokenResponse.class)
                .returnResult()
                .getResponseBody();
        return response.accessToken();
    }
}
