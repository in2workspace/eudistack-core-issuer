package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.domain.spi.KmsImportPort;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
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

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Integration test — AC-05: When both planAEnabled and planBEnabled are false (deploy-safe
 * defaults), the JWKS endpoint returns exactly one key and NO migration ports are invoked.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-a-enabled=false",
        "issuer.dome.key-migration.plan-b-enabled=false"
})
@DisplayName("AC-05: KeyMigration defaults — feature flags off, JWKS returns single key, no migration calls")
class KeyMigrationDefaultsIT {

    private static final String JWKS_URI = "/.well-known/jwks.json";

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private KmsKeyMigrationRepositoryPort migrationRepository;

    @MockitoBean
    private KmsImportPort kmsImportPort;

    @MockitoBean
    private VaultExportPort vaultExportPort;

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

    @Test
    @DisplayName("getJwks_WhenBothPlansDisabled_ReturnsSingleKeyWithoutCallingMigrationPorts")
    void getJwks_WhenBothPlansDisabled_ReturnsSingleKeyWithoutCallingMigrationPorts() {
        // Act + Assert — HTTP level
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

        // Assert — no migration infrastructure was touched
        verify(kmsImportPort, never()).describeKey(Mockito.any());
        verify(kmsImportPort, never()).getParametersForImport(Mockito.any());
        verify(vaultExportPort, never()).exportWrapped(Mockito.any(), Mockito.any());
    }
}

