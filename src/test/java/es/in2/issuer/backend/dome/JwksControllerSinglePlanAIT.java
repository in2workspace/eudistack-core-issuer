package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Integration test — AC-06 (plan A path).
 *
 * <p>Verifies that {@code GET /.well-known/jwks.json} returns exactly one EC P-256 key
 * when plan B re-issuance is disabled (the default / plan A state).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-b-enabled=false"
})
@DisplayName("JWKS endpoint returns single key when plan B is disabled")
class JwksControllerSinglePlanAIT {

    private static final String JWKS_URI = "/.well-known/jwks.json";

    @Autowired
    private WebTestClient webTestClient;

    /**
     * No implementation of this port exists yet; mock it so the Spring context starts.
     * With planBEnabled=false, DomeJwkProvider never calls it.
     */
    @MockitoBean
    private KmsKeyMigrationRepositoryPort migrationRepository;

    @Test
    @DisplayName("JWKS endpoint returns HTTP 200 with a single EC P-256 key when plan B is disabled")
    void getJwks_WhenPlanBDisabled_ReturnsSingleEcKey() {
        // Act + Assert
        webTestClient.get()
                .uri(JWKS_URI)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.keys").isArray()
                .jsonPath("$.keys.length()").isEqualTo(1)
                .jsonPath("$.keys[0].kty").isEqualTo("EC")
                .jsonPath("$.keys[0].crv").isEqualTo("P-256");
    }
}

