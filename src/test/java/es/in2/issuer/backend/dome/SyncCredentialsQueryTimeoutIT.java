package es.in2.issuer.backend.dome;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.time.Duration;

import static es.in2.issuer.backend.dome.support.DpopTestUtils.generateValidDpop;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsQueryTimeoutIT {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private CredentialSyncPort credentialSyncPort;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    @Test
    @DisplayName("ES-07: 500 Internal Server Error when query times out")
    void queryTimeout() {
        when(tenantConfigPort.requireConfig(anyString())).thenReturn(Mono.empty());
        // Simulating a delay of 6 seconds (workflow timeout is 5s)
        when(credentialSyncPort.findByHolderKey(anyString(), any()))
                .thenReturn(Flux.just(new ObjectMapper().createObjectNode())
                        .cast(JsonNode.class)
                        .delayElements(Duration.ofSeconds(6)));

        String body = "{\"idempotencyKey\": \"018f2a99-9b80-7fc4-a82f-2c8e3100b465\", \"holderKeyThumbprint\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}";

        webTestClient
                .mutate()
                .responseTimeout(java.time.Duration.ofSeconds(10))
                .build()
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