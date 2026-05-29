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
public class SyncCredentialsInvalidIdempotencyKeyIT {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    @DisplayName("ES-02: 400 Bad Request when IdempotencyKey is not a valid UUID")
    void invalidIdempotencyKey() {
        String invalidBody = "{\"idempotencyKey\": \"not-a-uuid\", \"holderKeyThumbprint\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}";

        webTestClient
                .mutateWith(csrf())
                .mutateWith(mockJwt().jwt(builder -> builder
                        .claim("tenant", "dome")
                        .claim("scope", "DomeRecovery/Sync")
                ))
                .post().uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(invalidBody)
                .exchange()
                .expectStatus().isBadRequest();
    }
}