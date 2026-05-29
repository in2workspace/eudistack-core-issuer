package es.in2.issuer.backend.dome;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import org.junit.jupiter.api.BeforeEach;
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

import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsDpopRejectionIT {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private CredentialSyncPort credentialSyncPort;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final String requestBody = """
            {
                "idempotencyKey": "018f2a99-9b80-7fc4-a82f-2c8e3100b468",
                "holderKeyThumbprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
            """;

    @BeforeEach
    void setUpMocks() {
        JsonNode mockCredential = objectMapper.createObjectNode()
                .put("format", "vc+sd-jwt")
                .put("credential", "dummy-jwt");
        when(tenantConfigPort.requireConfig(anyString())).thenReturn(Mono.empty());
        when(credentialSyncPort.findByHolderKey(anyString(), any())).thenReturn(Flux.just(mockCredential));
    }

    @Test
    @DisplayName("AC-07.1: Rejects request with 401 when DPoP header is completely missing")
    void missingDpopHeaderReturns401() {
        webTestClient.mutateWith(csrf())
                .mutateWith(mockJwt().jwt(b -> b.claim("tenant", "dome").claim("scope", "DomeRecovery/Sync")))
                .post().uri("/internal/dome/sync-credentials")
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody)
                // Notice: No .header("DPoP", ...) is added
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader()
                .valueEquals("X-DPoP-Rejection-Reason", "missing DPoP header");
    }

    @Test
    @DisplayName("AC-07.2: Rejects request with 401 when DPoP signature is broken")
    void brokenDpopSignatureReturns401() {
        // A valid looking JWT format but with a manipulated/broken signature part
        String brokenDpop = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0.eyJqdGkiOiIxMjM0In0.broken-signature-xyz";

        webTestClient.mutateWith(csrf())
                .mutateWith(mockJwt().jwt(b -> b.claim("tenant", "dome").claim("scope", "DomeRecovery/Sync")))
                .post().uri("/internal/dome/sync-credentials")
                .header("DPoP", brokenDpop)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader()
                .valueEquals("X-DPoP-Rejection-Reason", "invalid DPoP signature");
    }

    @Test
    @DisplayName("AC-07.3: HTM mismatch -> 401")
    void dpopHtmMismatchReturns401() {
        String dpop = createDpop("GET", "/internal/dome/sync-credentials");
        webTestClient.mutateWith(csrf()).mutateWith(mockJwt())
                .post().uri("/internal/dome/sync-credentials")
                .header("DPoP", dpop)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals("X-DPoP-Rejection-Reason", "invalid htm");
    }

    @Test
    @DisplayName("AC-07.4: IAT expired -> 401")
    void iatExpired() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"jti\":\"" + UUID.randomUUID() + "\",\"htm\":\"POST\",\"htu\":\"/internal/dome/sync-credentials\",\"iat\":" + (Instant.now().getEpochSecond() - 600) + "}").getBytes()
        );
        String expiredDpop = header + "." + payload + ".sig";

        webTestClient.mutateWith(csrf()).mutateWith(mockJwt())
                .post().uri("/internal/dome/sync-credentials")
                .header("DPoP", expiredDpop)
                .contentType(MediaType.APPLICATION_JSON).bodyValue(requestBody)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals("X-DPoP-Rejection-Reason", "iat expired");
    }

    private String createDpop(String htm, String htu) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"jti\":\"" + UUID.randomUUID() + "\",\"htm\":\"" + htm + "\",\"htu\":\"" + htu + "\",\"iat\":" + Instant.now().getEpochSecond() + "}").getBytes()
        );
        return header + "." + payload + ".valid-signature";
    }
}