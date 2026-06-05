package es.in2.issuer.backend.dome;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import es.in2.issuer.backend.dome.infrastructure.observability.SyncCredentialsAuditLogger;
import static es.in2.issuer.backend.dome.support.DpopTestUtils.generateValidDpop;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsCacheCollisionIT {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private CredentialSyncPort credentialSyncPort;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    @MockitoBean
    private SyncCredentialsAuditLogger auditLogger;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("ES-05: Same idempotencyKey but different holder is correctly distinguished (No collision)")
    void syncCredentialsCacheCollision() {
        String idempotencyKey = DomeSyncFixtureFactory.generateIdempotencyKey();
        String holder1 = DomeSyncFixtureFactory.HOLDER_1_THUMBPRINT;
        String holder2 = DomeSyncFixtureFactory.HOLDER_2_THUMBPRINT;

        JsonNode mockCredential = objectMapper.createObjectNode()
                .put("format", "vc+sd-jwt")
                .put("credential", "dummy-jwt");

        when(tenantConfigPort.requireConfig(anyString())).thenReturn(Mono.empty());
        when(credentialSyncPort.findByHolderKey(anyString(), any())).thenReturn(Flux.just(mockCredential));

        String requestBody1 = """
                {
                    "idempotencyKey": "%s",
                    "holderKeyThumbprint": "%s"
                }
                """.formatted(idempotencyKey, holder1);

        String requestBody2 = """
                {
                    "idempotencyKey": "%s",
                    "holderKeyThumbprint": "%s"
                }
                """.formatted(idempotencyKey, holder2);

        // Request with holder 1
        webTestClient
                .mutateWith(csrf())
                .mutateWith(mockJwt().jwt(builder -> builder.claim("tenant", "dome").claim("scope", "DomeRecovery/Sync")))
                .post()
                .uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody1)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Idempotent-Replay");

        // Request with holder 2 (same idempotencyKey)
        webTestClient
                .mutateWith(csrf())
                .mutateWith(mockJwt().jwt(builder -> builder.claim("tenant", "dome").claim("scope", "DomeRecovery/Sync")))
                .post()
                .uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody2)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Idempotent-Replay");

        // Verify that they were processed as two different requests (2 DB calls)
        verify(credentialSyncPort, times(2)).findByHolderKey(anyString(), any());
    }
}
