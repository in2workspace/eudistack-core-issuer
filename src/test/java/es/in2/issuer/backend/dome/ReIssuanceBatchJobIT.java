package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.application.workflow.IssueSignedCredentialWorkflow;
import es.in2.issuer.backend.dome.application.workflow.ReissuanceBatchWorkflow;
import es.in2.issuer.backend.dome.application.workflow.ReissuanceBatchWorkflow.BatchSummary;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.KmsImportPort;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.dome.fixtures.DomeKeyMigrationFixtureFactory;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration test — AC-03: Plan-B batch re-issuance processes 5 active,
 * skips 1 expired + 1 revoked, fails 0.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Testcontainers
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-b-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=batch-legacy-key",
        "issuer.dome.key-migration.kms-alias-v2=alias/dome/signing-v2"
})
@DisplayName("AC-03: ReIssuanceBatch — 5 ok, 2 skipped, 0 failed")
class ReIssuanceBatchJobIT {

    private static final String LEGACY_KEY_ID = "batch-legacy-key";

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
    private ReissuanceBatchWorkflow reissuanceBatchWorkflow;

    @Autowired
    private KmsKeyMigrationRepositoryPort migrationRepo;

    @MockitoBean
    private KmsImportPort kmsImportPort;

    @MockitoBean
    private VaultExportPort vaultExportPort;

    @MockitoBean
    private IssuanceRepository issuanceRepository;

    @MockitoBean
    private IssueSignedCredentialWorkflow issueSignedCredentialWorkflow;

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
    void setupFixtures() {
        // Arrange — insert a PENDING migration record for the legacy key
        migrationRepo.findByLegacyKeyId(new LegacyKeyId(LEGACY_KEY_ID))
                .switchIfEmpty(migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(LEGACY_KEY_ID)))
                .block();

        // Arrange — 5 active, 1 expired, 1 revoked credentials
        var credentials = Flux.just(
                DomeKeyMigrationFixtureFactory.activeIssuance(),
                DomeKeyMigrationFixtureFactory.activeIssuance(),
                DomeKeyMigrationFixtureFactory.activeIssuance(),
                DomeKeyMigrationFixtureFactory.activeIssuance(),
                DomeKeyMigrationFixtureFactory.activeIssuance(),
                DomeKeyMigrationFixtureFactory.expiredIssuance(),
                DomeKeyMigrationFixtureFactory.revokedIssuance()
        );
        when(issuanceRepository.findAllOrderByUpdatedDesc()).thenReturn(credentials);

        // IssueSignedCredentialWorkflow: always succeeds returning a dummy signed credential
        when(issueSignedCredentialWorkflow.reissue(any()))
                .thenReturn(Mono.just("{\"vc\":\"signed-credential\"}"));
    }

    @Test
    @DisplayName("execute_WithFiveActiveAndTwoSkippable_ReturnsBatchSummaryFiveOkTwoSkipped")
    void execute_WithFiveActiveAndTwoSkippable_ReturnsBatchSummaryFiveOkTwoSkipped() {
        // Act
        BatchSummary result = reissuanceBatchWorkflow.execute(LEGACY_KEY_ID).block();

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.ok()).isEqualTo(5);
        assertThat(result.skipped()).isEqualTo(2);
        assertThat(result.failed()).isEqualTo(0);
    }
}

