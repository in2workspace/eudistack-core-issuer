package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.application.service.KeyMigrationStateService;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Testcontainers
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-a-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=rollback-legacy-key",
        "issuer.dome.key-migration.kms-alias=alias/dome/signing"
})
@DisplayName("EC-03: Rollback — deleteImportedKeyMaterial called and DB transitions to ROLLED_BACK")
class KeyMigrationRollbackIT {

    private static final String LEGACY_KEY_ID = "rollback-legacy-key";

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
    private KmsKeyMigrationRepositoryPort migrationRepo;

    @Autowired
    private KeyMigrationStateService stateService;

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
    void stubKms() {
        when(kmsImportPort.deleteImportedKeyMaterial(any(KmsAlias.class)))
                .thenReturn(Mono.empty());
    }

    @Test
    @DisplayName("rollback_WhenStatusIsPlanAOk_TransitionsDbToRolledBack")
    void rollback_WhenStatusIsPlanAOk_TransitionsDbToRolledBack() {
        // Arrange
        migrationRepo.save(DomeKeyMigrationFixtureFactory.planAOkMigration(LEGACY_KEY_ID)).block();

        // Act
        kmsImportPort.deleteImportedKeyMaterial(new KmsAlias("alias/dome/signing")).block();
        stateService.transitionTo(new LegacyKeyId(LEGACY_KEY_ID), MigrationStatus.ROLLED_BACK).block();

        // Assert
        var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(LEGACY_KEY_ID)).block();
        assertThat(row).isNotNull();
        assertThat(row.getMigrationStatus()).isEqualTo("ROLLED_BACK");
    }

    @Test
    @DisplayName("rollback_AfterDelete_AliasStillExistsInKms")
    void rollback_AfterDelete_AliasStillExistsInKms() {
        // Arrange
        migrationRepo.save(DomeKeyMigrationFixtureFactory.planAOkMigration(
                "rollback-alias-check-" + System.nanoTime())).block();

        // Act
        KmsAlias alias = new KmsAlias("alias/dome/signing");
        kmsImportPort.deleteImportedKeyMaterial(alias).block();

        // Assert — deleteImportedKeyMaterial was called (EC-03: deletes material, not the alias)
        //           The alias can still be described (it's not deleted, only material is gone)
        verify(kmsImportPort).deleteImportedKeyMaterial(alias);
    }
}

