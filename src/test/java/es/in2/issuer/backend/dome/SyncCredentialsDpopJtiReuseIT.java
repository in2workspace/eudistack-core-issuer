package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static es.in2.issuer.backend.dome.support.DpopTestUtils.generateDpopWithJti;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsDpopJtiReuseIT {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private CredentialSyncPort credentialSyncPort;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    @Test
    @DisplayName("NFR-S-144-04: Rejects request with 401 when JTI is reused within TTL window")
    void dpopJtiReuse() {
        when(tenantConfigPort.requireConfig(anyString())).thenReturn(Mono.empty());
        when(credentialSyncPort.findByHolderKey(anyString(), any())).thenReturn(Flux.empty());

        String body = """
                {"idempotencyKey": "018f2a99-9b80-7fc4-a82f-2c8e3100b468", "holderKeyThumbprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
                """;

        String reusedJti = UUID.randomUUID().toString();
        String dpop = generateDpopWithJti("POST", "/internal/dome/sync-credentials", reusedJti);

        // 1st request: Success
        webTestClient
                .mutateWith(csrf())
                // We inject a mocked JWT with invalid claims (wrong scope)
                .mutateWith(mockJwt().jwt(builder -> builder
                        .claim("tenant", "dome")
                        .claim("scope", "DomeRecovery/Sync")
                ))
                .post().uri("/internal/dome/sync-credentials")
                .header("DPoP", dpop)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body)
                .exchange().expectStatus().isOk();

        // 2nd request: Same JTI -> 401 Unauthorized
        webTestClient
                .mutateWith(csrf())
                .mutateWith(mockJwt().jwt(builder -> builder
                        .claim("tenant", "dome")
                        .claim("scope", "DomeRecovery/Sync")
                ))
                .post().uri("/internal/dome/sync-credentials")
                .header("DPoP", dpop)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(body)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals("X-DPoP-Rejection-Reason", "replayed jti");
    }
}