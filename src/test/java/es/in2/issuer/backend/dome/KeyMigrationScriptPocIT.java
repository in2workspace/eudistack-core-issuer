package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.DomeSigningKeyRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.DomeKeyMigrationRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.dome.fixtures.DomeKeyMigrationFixtureFactory;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.security.KeyPair;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"test", "key-migration"})
@Testcontainers
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-a-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=poc-test-key"
})
@DisplayName("AC-01: PoC completa el flujo Vault→DB y transiciona a POC_OK")
class KeyMigrationScriptPocIT {

    @Container
    static final PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:15-alpine")
                    .withInitScript("db/dome-migration-it.sql");

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.r2dbc.url", () -> String.format(
                "r2dbc:postgresql://%s:%d/%s",
                postgres.getHost(), postgres.getMappedPort(5432), postgres.getDatabaseName()));
        registry.add("spring.r2dbc.username", postgres::getUsername);
        registry.add("spring.r2dbc.password", postgres::getPassword);
        registry.add("spring.flyway.url", postgres::getJdbcUrl);
    }

    @Autowired
    private KeyMigrationWorkflow keyMigrationWorkflow;

    @Autowired
    private DomeKeyMigrationRepositoryPort migrationRepo;

    @Autowired
    private DomeSigningKeyRepositoryPort domeSigningKeyRepo;

    @MockitoBean
    private VaultExportPort vaultExportPort;

    private String legacyKeyId;
    private KeyPair keyPair;

    @BeforeEach
    void stubMocks() {
        legacyKeyId = "poc-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        keyPair = DomeKeyMigrationFixtureFactory.generateEcP256KeyPair();
        when(vaultExportPort.exportPrivateKey(any()))
                .thenReturn(Mono.just(keyPair.getPrivate().getEncoded()));
    }

    @Test
    @DisplayName("executePoc — when Vault exports valid key — transitions to POC_OK")
    void executePoc_WhenVaultExportsValidKey_TransitionsToPocOk() {
        // Act
        keyMigrationWorkflow.executePoc(legacyKeyId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                .block();

        // Assert
        var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(legacyKeyId)).block();
        assertThat(row).isNotNull();
        assertThat(row.getMigrationStatus()).isEqualTo("POC_OK");
    }

    @Test
    @DisplayName("executePoc — when Vault exports valid key — key stored active in DB")
    void executePoc_WhenVaultExportsValidKey_KeyStoredActiveInDb() {
        // Act
        keyMigrationWorkflow.executePoc(legacyKeyId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                .block();

        // Assert
        var key = domeSigningKeyRepo.findActiveByLegacyKeyId(legacyKeyId).block();
        assertThat(key).isNotNull();
        assertThat(key.isActive()).isTrue();
    }

    @TestConfiguration
    static class TenantStubConfiguration {

        @Bean
        @Primary
        TenantRegistryService tenantRegistryServiceStub() {
            return new TenantRegistryService() {
                @Override
                public Mono<List<String>> getActiveTenantSchemas() {
                    return Mono.just(List.of("localhost"));
                }

                @Override
                public Mono<String> getTenantType(String schemaName) {
                    return Mono.empty();
                }
            };
        }
    }
}

