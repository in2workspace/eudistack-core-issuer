package es.in2.issuer.backend.apiclient.infrastructure.it;

import es.in2.issuer.backend.oidc4vci.domain.model.OAuthErrorResponse;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves schema-per-tenant isolation for {@code api_client} lookups
 * (EUD-75, US-02): the SAME {@code client_id} is registered in two different
 * tenant schemas with different secrets, and a secret only authenticates
 * against the tenant it was issued for. A leak here would mean the R2DBC
 * {@code search_path} (set per-connection from {@code X-Tenant}, see
 * {@code TenantAwareConnectionFactoryDecorator}) is not being honored by the
 * {@code api_client} lookup.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IntakeTenantAuthorizationIT extends PostgresIntegrationBase {

    private static final String TENANT_A = "e2e-tenant-a";
    private static final String TENANT_B = "e2e-tenant-b";
    private static final String SHARED_CLIENT_ID = "shared-intake-client";
    private static final String SECRET_A = "s3cr3t-tenant-a-pw";
    private static final String SECRET_B = "s3cr3t-tenant-b-pw";

    @BeforeAll
    void seedApiClients() {
        seedApiClient(TENANT_A, SHARED_CLIENT_ID, SECRET_A, true, "ACTIVE").block();
        seedApiClient(TENANT_B, SHARED_CLIENT_ID, SECRET_B, true, "ACTIVE").block();
    }

    @Test
    void exchangeToken_tenantAWithOwnSecret_succeeds() {
        requestToken(TENANT_A, SHARED_CLIENT_ID, SECRET_A)
                .expectStatus().isOk();
    }

    @Test
    void exchangeToken_tenantBWithOwnSecret_succeeds() {
        requestToken(TENANT_B, SHARED_CLIENT_ID, SECRET_B)
                .expectStatus().isOk();
    }

    @Test
    void exchangeToken_tenantAWithTenantBSecret_isRejected() {
        OAuthErrorResponse response = requestToken(TENANT_A, SHARED_CLIENT_ID, SECRET_B)
                .expectStatus().isUnauthorized()
                .expectBody(OAuthErrorResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(response).isNotNull();
        assertThat(response.error()).isEqualTo("invalid_client");
    }

    @Test
    void exchangeToken_tenantBWithTenantASecret_isRejected() {
        OAuthErrorResponse response = requestToken(TENANT_B, SHARED_CLIENT_ID, SECRET_A)
                .expectStatus().isUnauthorized()
                .expectBody(OAuthErrorResponse.class)
                .returnResult()
                .getResponseBody();

        assertThat(response).isNotNull();
        assertThat(response.error()).isEqualTo("invalid_client");
    }
}
