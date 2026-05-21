package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration test — ES-03 (tenant not configured / defensive fallback).
 *
 * <p>Verifies that {@code GET /.well-known/jwks.json} gracefully falls back to
 * a single-key response (no HTTP 5xx) when plan B is enabled but no
 * {@code kms_key_migration} row exists for the configured {@code legacyKeyId}.
 * This prevents outages during partial rollouts or misconfigured deployments.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-b-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=unknown-legacy-key"
})
@DisplayName("JWKS endpoint falls back to single key when no migration row exists for tenant")
class JwksControllerTenantNotConfiguredIT {

    private static final String JWKS_URI = "/.well-known/jwks.json";

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private KmsKeyMigrationRepositoryPort migrationRepository;

    @BeforeEach
    void setUp() {
        // Arrange — simulate ES-03: no row found in kms_key_migration for the tenant
        when(migrationRepository.findByLegacyKeyId(any(LegacyKeyId.class)))
                .thenReturn(Mono.empty());
    }

    @Test
    @DisplayName("JWKS endpoint returns HTTP 200 with a single key when tenant has no migration row")
    void getJwks_WhenNoMigrationRowExists_ReturnsSingleKeyWithoutError() {
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

