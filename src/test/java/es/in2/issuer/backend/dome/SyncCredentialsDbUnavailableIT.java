package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.dome.support.DpopTestUtils.generateValidDpop;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsDbUnavailableIT {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private CredentialSyncPort credentialSyncPort;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    @Test
    @DisplayName("ES-06: 500 Internal Server Error when DB is unreachable")
    void dbUnavailable() {
        when(tenantConfigPort.requireConfig(anyString())).thenReturn(Mono.empty());
        when(credentialSyncPort.findByHolderKey(anyString(), any()))
                .thenReturn(Flux.error(new DataAccessResourceFailureException("DB connection failed")));

        String body = "{\"idempotencyKey\": \"018f2a99-9b80-7fc4-a82f-2c8e3100b468\", \"holderKeyThumbprint\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}";

        webTestClient
                .mutateWith(csrf())
                .mutateWith(mockJwt().jwt(builder -> builder
                        .claim("tenant", "dome")
                        .claim("scope", "DomeRecovery/Sync")
                ))
                .post().uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().is5xxServerError();
    }
}