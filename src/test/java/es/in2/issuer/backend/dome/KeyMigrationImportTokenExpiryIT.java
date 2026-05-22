package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow;
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

/**
 * Integration test — EC-02: Import-token expiry is retried up to 3 times.
 * Succeeds on the 3rd attempt and transitions DB to PLAN_A_OK.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Testcontainers
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-a-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=retry-legacy-key",
        "issuer.dome.key-migration.kms-alias=alias/dome/signing"
})
@DisplayName("EC-02: ImportTokenExpiry — retries twice then succeeds → PLAN_A_OK")
class KeyMigrationImportTokenExpiryIT {

    private static final String LEGACY_KEY_ID = "retry-legacy-key";

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

    /**
     * Synthetic exception whose simple class name contains "ExpiredImportToken"
     * — required by {@code KeyMigrationWorkflow.isImportTokenExpiry()}.
     */
    static class ExpiredImportTokenException extends RuntimeException {
        ExpiredImportTokenException(String msg) {
            super(msg);
        }
    }

    @BeforeEach
    void stubRetries() {
        when(kmsImportPort.describeKey(any(KmsAlias.class)))
                .thenReturn(Mono.just(new KmsImportPort.KmsKeyDescription("id", "SIGN_VERIFY", true)));
        when(kmsImportPort.getParametersForImport(any(KmsAlias.class)))
                .thenReturn(Mono.just(new KmsImportPort.KmsImportParameters("tok", "pub")));
        when(vaultExportPort.exportWrapped(any(LegacyKeyId.class), any()))
                .thenReturn(Mono.just(new EncryptedKeyEnvelope(new byte[]{7}, "RSAES_OAEP_SHA_256", "")));

        // Arrange — first 2 calls to importKeyMaterial fail with ExpiredImportTokenException,
        // 3rd call succeeds → Reactor retryWhen(Retry.max(3).filter(isImportTokenExpiry)) handles it
        when(kmsImportPort.importKeyMaterial(any(), any(), any()))
                .thenReturn(Mono.error(new ExpiredImportTokenException("token expired")))
                .thenReturn(Mono.error(new ExpiredImportTokenException("token expired")))
                .thenReturn(Mono.empty());

        when(kmsImportPort.sign(any(KmsAlias.class), any()))
                .thenReturn(Mono.just("c2ln"));
    }

    @Test
    @DisplayName("executeProduction_WhenImportTokenExpiresTwice_RetriesAndTransitionsToPlanAOk")
    void executeProduction_WhenImportTokenExpiresTwice_RetriesAndTransitionsToPlanAOk() {
        // Act
        keyMigrationWorkflow.executeProduction(LEGACY_KEY_ID).block();

        // Assert — workflow retried and eventually succeeded
        var row = migrationRepo.findByLegacyKeyId(new LegacyKeyId(LEGACY_KEY_ID)).block();
        assertThat(row).isNotNull();
        assertThat(row.getMigrationStatus()).isEqualTo("PLAN_A_OK");
    }
}

