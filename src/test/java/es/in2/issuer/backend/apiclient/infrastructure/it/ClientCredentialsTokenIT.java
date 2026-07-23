package es.in2.issuer.backend.apiclient.infrastructure.it;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.oidc4vci.domain.model.OAuthErrorResponse;
import es.in2.issuer.backend.oidc4vci.domain.model.TokenResponse;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end coverage of {@code POST /oauth/token} with
 * {@code grant_type=client_credentials} (EUD-75, US-02): the M2M caller
 * authenticates against the {@code api_client} table of the tenant schema
 * resolved from {@code X-Tenant}, and receives a short-lived JWT carrying
 * {@code caller_type=M2M} and {@code can_trigger_issuance}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClientCredentialsTokenIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";
    private static final String ACTIVE_CLIENT_ID = "cct-active-client";
    private static final String ACTIVE_CLIENT_SECRET = "s3cr3t-active-pw";
    private static final String REVOKED_CLIENT_ID = "cct-revoked-client";
    private static final String REVOKED_CLIENT_SECRET = "s3cr3t-revoked-pw";

    @BeforeAll
    void seedApiClients() {
        seedApiClient(TENANT, ACTIVE_CLIENT_ID, ACTIVE_CLIENT_SECRET, true, "ACTIVE").block();
        seedApiClient(TENANT, REVOKED_CLIENT_ID, REVOKED_CLIENT_SECRET, true, "REVOKED").block();
    }

    @Test
    void exchangeToken_clientCredentialsValid_returnsM2mAccessTokenWithoutRefreshToken() throws Exception {
        TokenResponse response = requestToken(TENANT, ACTIVE_CLIENT_ID, ACTIVE_CLIENT_SECRET)
                .expectStatus().isOk()
                .expectBody(TokenResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(response).isNotNull();
        assertThat(response.accessToken()).isNotBlank();
        assertThat(response.tokenType()).isEqualTo("bearer");
        assertThat(response.refreshToken()).isNull();

        JWTClaimsSet claims = SignedJWT.parse(response.accessToken()).getJWTClaimsSet();
        assertThat(claims.getStringClaim("caller_type")).isEqualTo("M2M");
        assertThat(claims.getStringClaim("client_id")).isEqualTo(ACTIVE_CLIENT_ID);
        assertThat(claims.getBooleanClaim("can_trigger_issuance")).isTrue();
    }

    @Test
    void exchangeToken_wrongSecret_returnsInvalidClient() {
        OAuthErrorResponse response = requestToken(TENANT, ACTIVE_CLIENT_ID, "not-the-secret")
                .expectStatus().isUnauthorized()
                .expectBody(OAuthErrorResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(response).isNotNull();
        assertThat(response.error()).isEqualTo("invalid_client");
    }

    @Test
    void exchangeToken_unknownClientId_returnsInvalidClient() {
        OAuthErrorResponse response = requestToken(TENANT, "does-not-exist", "whatever")
                .expectStatus().isUnauthorized()
                .expectBody(OAuthErrorResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(response).isNotNull();
        assertThat(response.error()).isEqualTo("invalid_client");
    }

    @Test
    void exchangeToken_revokedClient_returnsInvalidClient() {
        requestToken(TENANT, REVOKED_CLIENT_ID, REVOKED_CLIENT_SECRET)
                .expectStatus().isUnauthorized()
                .expectBody(OAuthErrorResponse.class)
                .value(error -> assertThat(error.error()).isEqualTo("invalid_client"));
    }
}
