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
public class SyncCredentialsMissingFieldsIT {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    @DisplayName("ES-01: 400 Bad Request when fields are missing")
    void missingFields() {
        // Body missing the 'holderKeyThumbprint' field
        String invalidBody = "{\"idempotencyKey\": \"018f2a99-9b80-7fc4-a82f-2c8e3100b468\"}";

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
