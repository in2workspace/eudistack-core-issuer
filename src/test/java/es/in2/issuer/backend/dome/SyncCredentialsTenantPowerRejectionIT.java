package es.in2.issuer.backend.dome;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import static es.in2.issuer.backend.dome.support.DpopTestUtils.generateValidDpop;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsTenantPowerRejectionIT {
    @Autowired
    private WebTestClient webTestClient;

    @Test
    @DisplayName("AC-08: Rejects request with 403 when tenant is not 'dome' and required scope is missing")
    void syncCredentialsRejectsInvalidTenantAndScope() {
        String idempotencyKey = "018f2a99-9b80-7fc4-a82f-2c8e3100b468";
        String thumbprint = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        String requestBody = """
                {
                    "idempotencyKey": "%s",
                    "holderKeyThumbprint": "%s"
                }
                """.formatted(idempotencyKey, thumbprint);

        webTestClient
                .mutateWith(csrf())
                // We inject a mocked JWT with invalid claims (wrong tenant and wrong scope)
                .mutateWith(mockJwt().jwt(builder -> builder
                        .claim("tenant", "invalid-tenant")
                        .claim("scope", "SomeOther/Scope")
                ))
                .post()
                .uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                // Should return 403 Forbidden based on SyncCredentialsAuthorizationManager
                .expectStatus().isForbidden();
    }

    @Test
    @DisplayName("AC-08: Rejects request with 403 when required scope is missing")
    void syncCredentialsRejectsInvalidScope() {
        String idempotencyKey = "018f2a99-9b80-7fc4-a82f-2c8e3100b468";
        String thumbprint = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        String requestBody = """
                {
                    "idempotencyKey": "%s",
                    "holderKeyThumbprint": "%s"
                }
                """.formatted(idempotencyKey, thumbprint);

        webTestClient
                .mutateWith(csrf())
                // We inject a mocked JWT with invalid claims (wrong tenant)
                .mutateWith(mockJwt().jwt(builder -> builder
                        .claim("tenant", "invalid-tenant")
                        .claim("scope", "DomeRecovery/Sync")
                ))
                .post()
                .uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                // Should return 403 Forbidden based on SyncCredentialsAuthorizationManager
                .expectStatus().isForbidden();
    }

    @Test
    @DisplayName("AC-08: Rejects request with 403 when tenant is not 'dome'")
    void syncCredentialsRejectsInvalidTenant() {
        String idempotencyKey = "018f2a99-9b80-7fc4-a82f-2c8e3100b468";
        String thumbprint = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        String requestBody = """
                {
                    "idempotencyKey": "%s",
                    "holderKeyThumbprint": "%s"
                }
                """.formatted(idempotencyKey, thumbprint);

        webTestClient
                .mutateWith(csrf())
                // We inject a mocked JWT with invalid claims (wrong scope)
                .mutateWith(mockJwt().jwt(builder -> builder
                        .claim("tenant", "dome")
                        .claim("scope", "SomeOther/Scope")
                ))
                .post()
                .uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                // Should return 403 Forbidden based on SyncCredentialsAuthorizationManager
                .expectStatus().isForbidden();
    }
}
