package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.domain.exception.TenantNotConfiguredException;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.dome.support.DpopTestUtils.generateValidDpop;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsTenantConfigMissingIT {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    @Test
    @DisplayName("ES-04: 503 Service Unavailable when tenant config is missing")
    void tenantConfigMissing() {
        when(tenantConfigPort.requireConfig(anyString()))
                .thenReturn(Mono.error(new TenantNotConfiguredException("Tenant not found")));

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
                .expectStatus().isEqualTo(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE);
    }
}