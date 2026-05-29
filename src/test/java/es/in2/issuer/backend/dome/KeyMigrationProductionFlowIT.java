package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow;
import es.in2.issuer.backend.dome.domain.exception.ConflictingMigrationStateException;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.DomeKeyMigrationRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.DomeSigningKeyRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.dome.fixtures.DomeKeyMigrationFixtureFactory;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"test", "key-migration"})
@Testcontainers
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-a-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=prod-test-key"
})
@DisplayName("KeyMigration — production flows: MIGRATED and ROLLED_BACK from POC_OK")
class KeyMigrationProductionFlowIT {

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
    void setup() {
        legacyKeyId = "prod-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        keyPair = DomeKeyMigrationFixtureFactory.generateEcP256KeyPair();
        when(vaultExportPort.exportPrivateKey(any()))
                .thenReturn(Mono.just(keyPair.getPrivate().getEncoded()));
        // Execute PoC to reach POC_OK as initial state
        keyMigrationWorkflow.executePoc(legacyKeyId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                .block();
    }

    @Nested
    @DisplayName("When executing production migration from POC_OK state")
    class WhenExecutingProductionMigrationFromPocOk {

        @Test
        @DisplayName("executeMigration — when state is POC_OK — transitions to MIGRATED")
        void executeMigration_WhenStateIsPocOk_TransitionsToMigrated() {
            // Act
            keyMigrationWorkflow.executeMigration(legacyKeyId)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();

            // Assert
            var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(legacyKeyId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            assertThat(row).isNotNull();
            assertThat(row.getMigrationStatus()).isEqualTo("MIGRATED");
        }

        @Test
        @DisplayName("executeMigration — when state is POC_OK — key remains active in DB")
        void executeMigration_WhenStateIsPocOk_KeyRemainsActiveInDb() {
            // Act
            keyMigrationWorkflow.executeMigration(legacyKeyId)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();

            // Assert
            var key = domeSigningKeyRepo.findActiveByLegacyKeyId(legacyKeyId)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            assertThat(key).isNotNull();
            assertThat(key.isActive()).isTrue();
        }

        @Test
        @DisplayName("executeMigration — when state is not POC_OK — throws ConflictingMigrationStateException")
        void executeMigration_WhenStateIsNotPocOk_ThrowsConflictingState() {
            // Arrange: use a fresh legacyKeyId with no state (PENDING / non-existent)
            String freshLegacyKeyId = "fresh-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

            // Act + Assert
            assertThatThrownBy(() -> keyMigrationWorkflow.executeMigration(freshLegacyKeyId)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block())
                    .isInstanceOf(ConflictingMigrationStateException.class);
        }
    }

    @Nested
    @DisplayName("When rolling back from POC_OK state")
    class WhenRollingBackFromPocOk {

        @Test
        @DisplayName("executeRollback — when state is POC_OK — transitions to ROLLED_BACK")
        void executeRollback_WhenStateIsPocOk_TransitionsToRolledBack() {
            // Act
            keyMigrationWorkflow.executeRollback(legacyKeyId)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();

            // Assert
            var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(legacyKeyId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            assertThat(row).isNotNull();
            assertThat(row.getMigrationStatus()).isEqualTo("ROLLED_BACK");
        }

        @Test
        @DisplayName("executeRollback — when state is POC_OK — key is deactivated in DB")
        void executeRollback_WhenStateIsPocOk_KeyIsDeactivatedInDb() {
            // Act
            keyMigrationWorkflow.executeRollback(legacyKeyId)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();

            // Assert: the key was deactivated, so findActiveByLegacyKeyId returns empty
            var key = domeSigningKeyRepo.findActiveByLegacyKeyId(legacyKeyId)
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            assertThat(key).isNull();
        }
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

