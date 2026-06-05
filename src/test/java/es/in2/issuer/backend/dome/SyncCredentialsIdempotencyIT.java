package es.in2.issuer.backend.dome;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsIdempotencyIT {

    @Autowired private WebTestClient webTestClient;

    @MockitoBean private CredentialSyncPort credentialSyncPort;
    @MockitoBean private TenantConfigPort tenantConfigPort;
    @MockitoBean private SyncCredentialsAuditLogger auditLogger;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("AC-04: Multiple POST requests with the same idempotencyKey return cached responses and add the Idempotent-Replay header")
    void syncCredentialsIdempotency() {
        String idempotencyKey = DomeSyncFixtureFactory.generateIdempotencyKey();
        String thumbprint = DomeSyncFixtureFactory.HOLDER_1_THUMBPRINT;

        JsonNode mockCredential = objectMapper.createObjectNode()
                .put("format", "vc+sd-jwt")
                .put("credential", "dummy-jwt");

        when(tenantConfigPort.requireConfig(anyString())).thenReturn(Mono.empty());
        when(credentialSyncPort.findByHolderKey(anyString(), any())).thenReturn(Flux.just(mockCredential));

        String requestBody = """
                {
                    "idempotencyKey": "%s",
                    "holderKeyThumbprint": "%s"
                }
                """.formatted(idempotencyKey, thumbprint);

        // Original request
        webTestClient
                .mutateWith(csrf())
                .mutateWith(mockJwt().jwt(builder -> builder.claim("tenant", "dome").claim("scope", "DomeRecovery/Sync")))
                .post()
                .uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("Idempotent-Replay"); // No debe existir la primera vez

        // Repeated request (Idempotency)
        webTestClient
                .mutateWith(csrf())
                .mutateWith(mockJwt().jwt(builder -> builder.claim("tenant", "dome").claim("scope", "DomeRecovery/Sync")))
                .post()
                .uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Idempotent-Replay", "true"); // AHORA SÍ debe existir

        // Verify that the database was queried only once; the second attempt was served from cache
        verify(credentialSyncPort, times(1)).findByHolderKey(anyString(), any());
    }
}
