package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

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

    @TestConfiguration
    static class TenantStubConfig {
        @Bean
        @Primary
        TenantRegistryService tenantRegistryService() {
            TenantRegistryService mock = Mockito.mock(TenantRegistryService.class);
            when(mock.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("localhost")));
            return mock;
        }
    }

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
