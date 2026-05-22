package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow;
import es.in2.issuer.backend.dome.domain.exception.KmsAliasNotProvisionedException;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.KmsImportPort;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.dome.fixtures.DomeKeyMigrationFixtureFactory;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration test — ES-02: When the KMS alias is not provisioned,
 * executePoc must surface KmsAliasNotProvisionedException and set DB status to FAILED.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Testcontainers
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-a-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=missing-alias-key",
        "issuer.dome.key-migration.kms-alias=alias/dome/missing"
})
@DisplayName("ES-02: KmsAliasMissing — KmsAliasNotProvisionedException thrown and DB set to FAILED")
class KeyMigrationKmsAliasMissingIT {

    private static final String LEGACY_KEY_ID = "missing-alias-key";

    @Container
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:15-alpine")
                    .withInitScript("db/dome-migration-it.sql");

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry r) {
        r.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s",
                postgres.getHost(), postgres.getFirstMappedPort(), postgres.getDatabaseName()));
        r.add("spring.r2dbc.username", postgres::getUsername);
        r.add("spring.r2dbc.password", postgres::getPassword);
        r.add("spring.flyway.url", postgres::getJdbcUrl);
        r.add("spring.flyway.username", postgres::getUsername);
        r.add("spring.flyway.password", postgres::getPassword);
        r.add("issuer.dome.key-migration.vault-endpoint", () -> "http://localhost:9999");
    }

    @Autowired
    private KeyMigrationWorkflow keyMigrationWorkflow;

    @Autowired
    private KmsKeyMigrationRepositoryPort migrationRepo;

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

    @BeforeEach
    void stubAliasNotProvisioned() {
        // Arrange — KMS alias does not exist → describeKey throws
        when(kmsImportPort.describeKey(any(KmsAlias.class)))
                .thenReturn(Mono.error(new KmsAliasNotProvisionedException(
                        "KMS alias not provisioned (ES-02): alias/dome/missing")));
    }

    @Test
    @DisplayName("executePoc_WhenAliasNotProvisioned_ThrowsKmsAliasNotProvisionedException")
    void executePoc_WhenAliasNotProvisioned_ThrowsKmsAliasNotProvisionedException() {
        // Arrange — insert a pending record so stateService has something to transition
        migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(LEGACY_KEY_ID)).block();

        // Act + Assert — exception surfaces to the caller
        assertThatThrownBy(() -> keyMigrationWorkflow.executePoc(LEGACY_KEY_ID).block())
                .isInstanceOf(KmsAliasNotProvisionedException.class);
    }

    @Test
    @DisplayName("executePoc_WhenAliasNotProvisioned_DbStatusSetToFailed")
    void executePoc_WhenAliasNotProvisioned_DbStatusSetToFailed() {
        // Arrange
        String uniqueKeyId = "missing-alias-" + System.nanoTime();
        migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(uniqueKeyId)).block();

        // Act
        try {
            keyMigrationWorkflow.executePoc(uniqueKeyId).block();
        } catch (KmsAliasNotProvisionedException ignored) { /* expected */ }

        // Assert — DB row is FAILED (fail-closed, AC-08)
        var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(uniqueKeyId)).block();
        assertThat(row).isNotNull();
        assertThat(row.getMigrationStatus()).isEqualTo("FAILED");
    }
}

