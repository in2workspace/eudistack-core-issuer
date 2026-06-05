package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import es.in2.issuer.backend.dome.infrastructure.observability.SyncCredentialsAuditLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.dome.support.DpopTestUtils.generateValidDpop;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsEmptyHolderIT {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private CredentialSyncPort credentialSyncPort;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    @MockitoBean
    private SyncCredentialsAuditLogger auditLogger;

    @Test
    @DisplayName("200 OK: Returns an empty list when the holder has no credentials")
    void syncCredentialsEmptyHolder() {

        String idempotencyKey = DomeSyncFixtureFactory.generateIdempotencyKey();
        String thumbprint = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        when(tenantConfigPort.requireConfig(anyString())).thenReturn(Mono.empty());
        when(credentialSyncPort.findByHolderKey(anyString(), any())).thenReturn(Flux.empty());

        String requestBody = """
                {
                    "idempotencyKey": "%s",
                    "holderKeyThumbprint": "%s"
                }
                """.formatted(idempotencyKey, thumbprint);

        webTestClient
                .mutateWith(csrf())
                .mutateWith(mockJwt().jwt(builder -> builder
                        .claim("tenant", "dome")
                        .claim("scope", "DomeRecovery/Sync")
                ))
                .post()
                .uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Idempotent-Replay")
                .expectBody()
                .jsonPath("$.credentials").isArray()
                .jsonPath("$.credentials.length()").isEqualTo(0); // Verificamos que viene vacío

        verify(auditLogger).logSyncEvent(anyString(), eq(idempotencyKey), eq("SUCCESS_DB_FETCH"));
    }
}
