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
@DisplayName("KeyMigration — fail-closed: errors always transition to FAILED")
class KeyMigrationFailClosedIT {

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

    @MockitoBean
    private VaultExportPort vaultExportPort;

    @MockitoBean
    private DomeSigningKeyRepositoryPort domeSigningKeyRepo;

    private String legacyKeyId;

    @BeforeEach
    void setUpId() {
        legacyKeyId = "fail-" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        // Default: no active key exists — each nested class can override for specific scenarios
        when(domeSigningKeyRepo.findActiveByLegacyKeyId(any())).thenReturn(Mono.empty());
    }

    @Nested
    @DisplayName("When Vault is unavailable")
    class WhenVaultIsUnavailable {

        @BeforeEach
        void setUp() {
            migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(legacyKeyId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            when(vaultExportPort.exportPrivateKey(any()))
                    .thenReturn(Mono.error(new RuntimeException("vault down")));
        }

        @Test
        @DisplayName("executePoc — when Vault fails — migration status is FAILED")
        void executePoc_WhenVaultFails_StatusIsFailed() {
            // Act
            try {
                keyMigrationWorkflow.executePoc(legacyKeyId)
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                        .block();
            } catch (Exception ignored) {
                // expected
            }

            // Assert
            var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(legacyKeyId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            assertThat(row).isNotNull();
            assertThat(row.getMigrationStatus()).isEqualTo("FAILED");
        }
    }

    @Nested
    @DisplayName("When saving key to DB fails")
    class WhenSavingKeyFails {

        @BeforeEach
        void setUp() {
            migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(legacyKeyId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            var keyPair = DomeKeyMigrationFixtureFactory.generateEcP256KeyPair();
            when(vaultExportPort.exportPrivateKey(any()))
                    .thenReturn(Mono.just(keyPair.getPrivate().getEncoded()));
            when(domeSigningKeyRepo.save(any()))
                    .thenReturn(Mono.error(new RuntimeException("db save failed")));
        }

        @Test
        @DisplayName("executePoc — when DB save fails — migration status is FAILED")
        void executePoc_WhenDbSaveFails_StatusIsFailed() {
            // Act
            try {
                keyMigrationWorkflow.executePoc(legacyKeyId)
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                        .block();
            } catch (Exception ignored) {
                // expected
            }

            // Assert
            var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(legacyKeyId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            assertThat(row).isNotNull();
            assertThat(row.getMigrationStatus()).isEqualTo("FAILED");
        }
    }

    @Nested
    @DisplayName("When signature validation fails")
    class WhenSignatureValidationFails {

        private static final byte[] INVALID_KEY_MATERIAL = new byte[32];

        @BeforeEach
        void setUp() {
            migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(legacyKeyId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            when(vaultExportPort.exportPrivateKey(any()))
                    .thenReturn(Mono.just(INVALID_KEY_MATERIAL));
            when(domeSigningKeyRepo.save(any()))
                    .thenReturn(Mono.just(
                            DomeKeyMigrationFixtureFactory.activeDomeSigningKey(legacyKeyId, INVALID_KEY_MATERIAL)));
            when(domeSigningKeyRepo.findActiveByLegacyKeyId(any()))
                    .thenReturn(Mono.just(
                            DomeKeyMigrationFixtureFactory.activeDomeSigningKey(legacyKeyId, INVALID_KEY_MATERIAL)));
        }

        @Test
        @DisplayName("executePoc — when key material is invalid — migration status is FAILED")
        void executePoc_WhenKeyMaterialInvalid_StatusIsFailed() {
            // Act
            try {
                keyMigrationWorkflow.executePoc(legacyKeyId)
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                        .block();
            } catch (Exception ignored) {
                // expected
            }

            // Assert
            var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(legacyKeyId))
                    .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "localhost"))
                    .block();
            assertThat(row).isNotNull();
            assertThat(row.getMigrationStatus()).isEqualTo("FAILED");
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
