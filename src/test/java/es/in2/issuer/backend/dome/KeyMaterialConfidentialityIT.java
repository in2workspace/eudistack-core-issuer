package es.in2.issuer.backend.dome;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow;
import es.in2.issuer.backend.dome.domain.model.keymigration.EncryptedKeyEnvelope;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.KmsKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationAuditEntry;
import es.in2.issuer.backend.dome.domain.spi.KmsImportPort;
import es.in2.issuer.backend.dome.domain.spi.KmsKeyMigrationRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import es.in2.issuer.backend.dome.infrastructure.adapter.persistence.R2dbcMigrationAuditRepository;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Integration test — AC-04 + NFR-S-143-01:
 * No sensitive key material (ciphertext, PEM headers, private key bytes) leaks into
 * structured logs during a PoC migration run.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "issuer.dome.key-migration.plan-a-enabled=true",
        "issuer.dome.key-migration.legacy-key-id=conf-legacy-key",
        "issuer.dome.key-migration.kms-alias=alias/dome/signing"
})
@DisplayName("AC-04 + NFR-S-143-01: No sensitive key material appears in logs")
class KeyMaterialConfidentialityIT {

    private static final String LEGACY_KEY_ID = "conf-legacy-key";

    @Autowired
    private KeyMigrationWorkflow keyMigrationWorkflow;

    @MockitoBean
    private KmsImportPort kmsImportPort;

    @MockitoBean
    private VaultExportPort vaultExportPort;

    @MockitoBean
    private KmsKeyMigrationRepositoryPort migrationRepository;

    @MockitoBean
    private R2dbcMigrationAuditRepository auditRepository;

    private Logger rootLogger;
    private ListAppender<ILoggingEvent> listAppender;

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
    void attachLogCapture() {
        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        listAppender = new ListAppender<>();
        listAppender.start();
        rootLogger.addAppender(listAppender);
    }

    @AfterEach
    void detachLogCapture() {
        if (rootLogger != null) {
            rootLogger.detachAppender(listAppender);
        }
    }

    @BeforeEach
    void stubMocks() {
        // Stub KMS import port — all operations succeed
        when(kmsImportPort.describeKey(any(KmsAlias.class)))
                .thenReturn(Mono.just(new KmsImportPort.KmsKeyDescription("kms-id", "SIGN_VERIFY", true)));
        when(kmsImportPort.getParametersForImport(any(KmsAlias.class)))
                .thenReturn(Mono.just(new KmsImportPort.KmsImportParameters("tok", "pubkey")));
        when(vaultExportPort.exportWrapped(any(LegacyKeyId.class), any()))
                .thenReturn(Mono.just(new EncryptedKeyEnvelope(new byte[]{9}, "RSAES_OAEP_SHA_256", "")));
        when(kmsImportPort.importKeyMaterial(any(), any(), any()))
                .thenReturn(Mono.empty());
        when(kmsImportPort.sign(any(KmsAlias.class), any()))
                .thenReturn(Mono.just("c2lnbmF0dXJl"));

        // Stub repository — allow state transitions
        KmsKeyMigration pending = KmsKeyMigration.builder()
                .id(java.util.UUID.randomUUID())
                .legacyKeyId(LEGACY_KEY_ID)
                .migrationStatus("PENDING")
                .replayAttempt(0)
                .createdAt(java.time.Instant.now())
                .updatedAt(java.time.Instant.now())
                .build();
        when(migrationRepository.findByLegacyKeyId(any(LegacyKeyId.class)))
                .thenReturn(Mono.empty()); // first call: no record → creates PENDING
        when(migrationRepository.save(any(KmsKeyMigration.class)))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(migrationRepository.updateStatus(any(LegacyKeyId.class), any()))
                .thenAnswer(inv -> {
                    KmsKeyMigration updated = pending;
                    return Mono.just(updated);
                });

        // Stub audit repository
        when(auditRepository.save(any(MigrationAuditEntry.class)))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));
        when(auditRepository.findBySourceRecordId(any()))
                .thenReturn(Mono.empty());
    }

    @Test
    @DisplayName("executePoc_DuringWorkflow_LogsContainNoCryptographicMaterial")
    void executePoc_DuringWorkflow_LogsContainNoCryptographicMaterial() {
        // Act
        try {
            keyMigrationWorkflow.executePoc(LEGACY_KEY_ID).block();
        } catch (Exception ignored) {
            // Even on failure, the log-content assertions must hold
        }

        // Assert — no log event contains sensitive key material
        List<String> logMessages = listAppender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .toList();

        assertThat(logMessages).noneMatch(msg -> msg.contains("-----BEGIN PRIVATE"));
        assertThat(logMessages).noneMatch(msg -> msg.contains("-----BEGIN EC PRIVATE"));
        assertThat(logMessages).noneMatch(msg -> msg.contains("privateKey"));
        // REDACTED string is allowed; raw ciphertext value must NOT appear
        assertThat(logMessages).noneMatch(msg ->
                msg.contains("ciphertext=") && !msg.contains("REDACTED"));
        // No suspiciously long base64 blobs that could be key material (>100 chars of base64)
        assertThat(logMessages).noneMatch(msg ->
                msg.matches("(?s).*[A-Za-z0-9+/]{100,}={0,2}.*")
                        && !msg.contains("c2lnbmF0dXJl")); // our test signature token
    }
}

