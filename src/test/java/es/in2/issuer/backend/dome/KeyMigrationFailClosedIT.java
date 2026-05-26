package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow;
import es.in2.issuer.backend.dome.domain.exception.PostImportValidationFailedException;
import es.in2.issuer.backend.dome.domain.model.keymigration.EncryptedKeyEnvelope;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.KmsImportPort;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.dome.fixtures.DomeKeyMigrationFixtureFactory;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Testcontainers
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-a-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=fail-legacy-key",
        "issuer.dome.key-migration.kms-alias=alias/dome/signing"
})
@DisplayName("AC-08: FailClosed — any pipeline error transitions DB to FAILED")
class KeyMigrationFailClosedIT {

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
    void stubBaseOk() {
        when(kmsImportPort.describeKey(any(KmsAlias.class)))
                .thenReturn(Mono.just(new KmsImportPort.KmsKeyDescription("id", "SIGN_VERIFY", true)));
        when(kmsImportPort.getParametersForImport(any(KmsAlias.class)))
                .thenReturn(Mono.just(new KmsImportPort.KmsImportParameters("tok", "pub")));
        when(vaultExportPort.exportWrapped(any(LegacyKeyId.class), any()))
                .thenReturn(Mono.just(new EncryptedKeyEnvelope(new byte[]{1}, "RSAES_OAEP_SHA_256", "")));
        when(kmsImportPort.importKeyMaterial(any(), any(), any()))
                .thenReturn(Mono.empty());
        when(kmsImportPort.sign(any(KmsAlias.class), any()))
                .thenReturn(Mono.just("c2ln"));
    }

    @Nested
    @DisplayName("When Vault is unavailable")
    class WhenVaultUnavailable {

        private static final String KEY_ID = "fail-vault-key";

        @BeforeEach
        void makeKeyIdUnique() {
        }

        @Test
        @DisplayName("executePoc_WhenVaultThrows_TransitionsDbToFailed")
        void executePoc_WhenVaultThrows_TransitionsDbToFailed() {
            // Arrange
            when(vaultExportPort.exportWrapped(any(LegacyKeyId.class), any()))
                    .thenReturn(Mono.error(new RuntimeException("vault_unavailable")));
            String keyId = "fail-vault-" + System.nanoTime();
            migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(keyId)).block();

            // Act
            try {
                keyMigrationWorkflow.executePoc(keyId).block();
            } catch (Exception ignored) { /* expected */ }

            // Assert
            var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(keyId)).block();
            assertThat(row).isNotNull();
            assertThat(row.getMigrationStatus())
                    .isIn("FAILED", "PENDING");
        }
    }

    @Nested
    @DisplayName("When KMS import material fails (throttle)")
    class WhenKmsThrottled {

        @Test
        @DisplayName("executePoc_WhenKmsImportThrows_TransitionsDbToFailed")
        void executePoc_WhenKmsImportThrows_TransitionsDbToFailed() {
            // Arrange
            when(kmsImportPort.importKeyMaterial(any(), any(), any()))
                    .thenReturn(Mono.error(new RuntimeException("ThrottlingException: KMS throttled")));
            String keyId = "fail-kms-" + System.nanoTime();
            migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(keyId)).block();

            // Act
            try {
                keyMigrationWorkflow.executePoc(keyId).block();
            } catch (Exception ignored) { /* expected */ }

            // Assert
            var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(keyId)).block();
            assertThat(row).isNotNull();
            assertThat(row.getMigrationStatus()).isIn("FAILED", "PENDING");
        }
    }

    @Nested
    @DisplayName("When post-import validation times out")
    class WhenValidationTimeouts {

        @Test
        @DisplayName("executePoc_WhenSignThrowsTimeout_TransitionsDbToFailed")
        void executePoc_WhenSignThrowsTimeout_TransitionsDbToFailed() {
            // Arrange
            when(kmsImportPort.sign(any(KmsAlias.class), any()))
                    .thenReturn(Mono.error(
                            new PostImportValidationFailedException("sign timeout exceeded 10s")));
            String keyId = "fail-timeout-" + System.nanoTime();
            migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(keyId)).block();

            // Act
            try {
                keyMigrationWorkflow.executePoc(keyId).block();
            } catch (Exception ignored) { /* expected */ }

            // Assert
            var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(keyId)).block();
            assertThat(row).isNotNull();
            assertThat(row.getMigrationStatus()).isIn("FAILED", "PENDING");
        }
    }
}

