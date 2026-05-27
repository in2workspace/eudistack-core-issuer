package es.in2.issuer.backend.dome;

import es.in2.issuer.backend.dome.application.workflow.IssueSignedCredentialWorkflow;
import es.in2.issuer.backend.dome.application.workflow.ReissuanceBatchWorkflow;
import es.in2.issuer.backend.dome.application.workflow.ReissuanceBatchWorkflow.BatchSummary;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.spi.KmsImportPort;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.dome.fixtures.DomeKeyMigrationFixtureFactory;
import es.in2.issuer.backend.dome.infrastructure.adapter.persistence.R2dbcMigrationAuditRepository;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Testcontainers
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-b-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=idempotent-legacy-key",
        "issuer.dome.key-migration.kms-alias-v2=alias/dome/signing-v2"
})
@DisplayName("AC-07: ReIssuanceBatch idempotency — second run produces no duplicate audit rows")
class ReIssuanceBatchJobIdempotencyIT {

    private static final String LEGACY_KEY_ID = "idempotent-legacy-key";

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

    @Autowired
    private R2dbcMigrationAuditRepository auditRepository;

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

    private static final UUID ISSUANCE_ID_1 = UUID.randomUUID();
    private static final UUID ISSUANCE_ID_2 = UUID.randomUUID();
    private static final UUID ISSUANCE_ID_3 = UUID.randomUUID();

    @BeforeEach
    void setupFixtures() {
        migrationRepo.findByLegacyKeyId(new LegacyKeyId(LEGACY_KEY_ID))
                .switchIfEmpty(migrationRepo.save(DomeKeyMigrationFixtureFactory.pendingMigration(LEGACY_KEY_ID)))
                .block();

        var c1 = DomeKeyMigrationFixtureFactory.activeIssuance();
        var c2 = DomeKeyMigrationFixtureFactory.activeIssuance();
        var c3 = DomeKeyMigrationFixtureFactory.activeIssuance();
        c1.setIssuanceId(ISSUANCE_ID_1);
        c2.setIssuanceId(ISSUANCE_ID_2);
        c3.setIssuanceId(ISSUANCE_ID_3);

        when(issuanceRepository.findAllOrderByUpdatedDesc())
                .thenReturn(Flux.just(c1, c2, c3));
        when(issueSignedCredentialWorkflow.reissue(any()))
                .thenReturn(Mono.just("{\"vc\":\"signed\"}"));
    }

    @Test
    @DisplayName("execute_CalledTwiceWithSameDataset_AuditRowsNotDuplicatedOnSecondRun")
    void execute_CalledTwiceWithSameDataset_AuditRowsNotDuplicatedOnSecondRun() {
        // Act
        BatchSummary first = reissuanceBatchWorkflow.execute(LEGACY_KEY_ID).block();

        BatchSummary second = reissuanceBatchWorkflow.execute(LEGACY_KEY_ID).block();

        // Assert
        assertThat(first).isNotNull();
        assertThat(first.ok()).isEqualTo(3);
        assertThat(first.failed()).isEqualTo(0);

        assertThat(second).isNotNull();
        assertThat(second.ok()).isEqualTo(0);
        assertThat(second.skipped()).isEqualTo(3);
        assertThat(second.failed()).isEqualTo(0);

        for (UUID issuanceId : List.of(ISSUANCE_ID_1, ISSUANCE_ID_2, ISSUANCE_ID_3)) {
            var entry = auditRepository.findOkBySourceRecordId(issuanceId).block();
            assertThat(entry).isNotNull()
                    .extracting(e -> e.getOutcome()).isEqualTo("OK");
        }
    }
}

