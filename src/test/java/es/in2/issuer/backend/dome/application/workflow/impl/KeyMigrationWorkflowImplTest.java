package es.in2.issuer.backend.dome.application.workflow.impl;

import es.in2.issuer.backend.dome.application.service.KeyMigrationStateService;
import es.in2.issuer.backend.dome.domain.exception.ConflictingMigrationStateException;
import es.in2.issuer.backend.dome.domain.model.keymigration.DomeKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.DomeSigningKeyRepositoryPort;
import es.in2.issuer.backend.dome.domain.spi.VaultExportPort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("KeyMigrationWorkflowImpl — unit")
class KeyMigrationWorkflowImplTest {

    @Mock
    private VaultExportPort vaultExportPort;
    @Mock
    private DomeSigningKeyRepositoryPort domeSigningKeyRepo;
    @Mock
    private KeyMigrationStateService stateService;

    @InjectMocks
    private KeyMigrationWorkflowImpl workflow;

    private static final String LEGACY_KEY_ID = "legacy-key-001";
    private static final String TENANT = "localhost";

    @BeforeEach
    void setUpSafeDefaults() {
        DomeKeyMigration failedStub = DomeKeyMigration.builder()
                .legacyKeyId(LEGACY_KEY_ID).migrationStatus(MigrationStatus.FAILED.name()).build();
        DomeKeyMigration pocOkStub = DomeKeyMigration.builder()
                .legacyKeyId(LEGACY_KEY_ID).migrationStatus(MigrationStatus.POC_OK.name()).build();
        DomeKeyMigration migratedStub = DomeKeyMigration.builder()
                .legacyKeyId(LEGACY_KEY_ID).migrationStatus(MigrationStatus.MIGRATED.name()).build();
        DomeKeyMigration rolledBackStub = DomeKeyMigration.builder()
                .legacyKeyId(LEGACY_KEY_ID).migrationStatus(MigrationStatus.ROLLED_BACK.name()).build();
        lenient().when(stateService.transitionTo(new LegacyKeyId(LEGACY_KEY_ID), MigrationStatus.FAILED))
                .thenReturn(Mono.just(failedStub));
        lenient().when(stateService.transitionTo(new LegacyKeyId(LEGACY_KEY_ID), MigrationStatus.POC_OK))
                .thenReturn(Mono.just(pocOkStub));
        lenient().when(stateService.transitionTo(new LegacyKeyId(LEGACY_KEY_ID), MigrationStatus.MIGRATED))
                .thenReturn(Mono.just(migratedStub));
        lenient().when(domeSigningKeyRepo.deactivateByLegacyKeyId(LEGACY_KEY_ID))
                .thenReturn(Mono.empty());
        lenient().when(stateService.transitionTo(new LegacyKeyId(LEGACY_KEY_ID), MigrationStatus.ROLLED_BACK))
                .thenReturn(Mono.just(rolledBackStub));
    }

    @Nested
    @DisplayName("executePoc — terminal state guard")
    class ExecutePocTerminalStateGuard {

        @Test
        @DisplayName("MIGRATED state — rejects with ConflictingMigrationStateException before any side effects")
        void executePoc_migratedState_rejectsWithConflictingException() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID))
                    .thenReturn(Mono.just(MigrationStatus.MIGRATED));

            // Act & Assert
            StepVerifier.create(
                    workflow.executePoc(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectErrorMatches(ex ->
                            ex instanceof ConflictingMigrationStateException
                            && ex.getMessage().contains("MIGRATED"))
                    .verify();

            verifyNoInteractions(vaultExportPort);
            verifyNoInteractions(domeSigningKeyRepo);
        }

        @Test
        @DisplayName("ROLLED_BACK state — rejects with ConflictingMigrationStateException before any side effects")
        void executePoc_rolledBackState_rejectsWithConflictingException() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID))
                    .thenReturn(Mono.just(MigrationStatus.ROLLED_BACK));

            // Act & Assert
            StepVerifier.create(
                    workflow.executePoc(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectErrorMatches(ex ->
                            ex instanceof ConflictingMigrationStateException
                            && ex.getMessage().contains("ROLLED_BACK"))
                    .verify();

            verifyNoInteractions(vaultExportPort);
            verifyNoInteractions(domeSigningKeyRepo);
        }

        @Test
        @DisplayName("MIGRATED state — does NOT attempt to record FAILED transition")
        void executePoc_migratedState_doesNotRecordFailedTransition() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID))
                    .thenReturn(Mono.just(MigrationStatus.MIGRATED));

            // Act & Assert
            StepVerifier.create(
                    workflow.executePoc(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectError(ConflictingMigrationStateException.class)
                    .verify();

            verify(stateService, never()).transitionTo(any(), eq(MigrationStatus.FAILED));
        }
    }

    @Nested
    @DisplayName("executePoc — tenant context validation")
    class ExecutePocTenantValidation {

        @Test
        @DisplayName("no tenant in context — errors with IllegalStateException")
        void executePoc_noTenantInContext_errorsWithIllegalStateException() {
            // Act & Assert
            StepVerifier.create(workflow.executePoc(LEGACY_KEY_ID))
                    .expectErrorMatches(ex -> ex instanceof IllegalStateException
                            && ex.getMessage().contains("Tenant domain must be present"))
                    .verify();

            verifyNoInteractions(stateService);
        }

        @Test
        @DisplayName("blank tenant in context — errors with IllegalStateException")
        void executePoc_blankTenantInContext_errorsWithIllegalStateException() {
            // Act & Assert
            StepVerifier.create(
                    workflow.executePoc(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "   ")))
                    .expectErrorMatches(ex -> ex instanceof IllegalStateException)
                    .verify();
        }
    }

    @Nested
    @DisplayName("executePoc — non-terminal states pass the pre-check")
    class ExecutePocNonTerminalStates {

        @Test
        @DisplayName("PENDING state — passes pre-check, proceeds to vault (vault error ≠ ConflictingMigrationStateException)")
        void executePoc_pendingState_passesPrecheckAndReachesVault() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID))
                    .thenReturn(Mono.just(MigrationStatus.PENDING));
            when(domeSigningKeyRepo.findActiveByLegacyKeyId(LEGACY_KEY_ID))
                    .thenReturn(Mono.empty());
            when(vaultExportPort.exportPrivateKey(new LegacyKeyId(LEGACY_KEY_ID)))
                    .thenReturn(Mono.error(new RuntimeException("vault_export_failed: " + LEGACY_KEY_ID)));

            // Act & Assert
            StepVerifier.create(
                    workflow.executePoc(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectErrorMatches(ex ->
                            ex instanceof RuntimeException
                            && !(ex instanceof es.in2.issuer.backend.dome.domain.exception.ConflictingMigrationStateException)
                            && ex.getMessage().contains("vault_export_failed"))
                    .verify();
        }

        @Test
        @DisplayName("POC_OK state (no active key in DB) — passes pre-check, reaches vault")
        void executePoc_pocOkStateNoActiveKey_passesPrecheckAndReachesVault() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID))
                    .thenReturn(Mono.just(MigrationStatus.POC_OK));
            when(domeSigningKeyRepo.findActiveByLegacyKeyId(LEGACY_KEY_ID))
                    .thenReturn(Mono.empty());
            when(vaultExportPort.exportPrivateKey(new LegacyKeyId(LEGACY_KEY_ID)))
                    .thenReturn(Mono.error(new RuntimeException("vault_export_failed: " + LEGACY_KEY_ID)));

            // Act & Assert
            StepVerifier.create(
                    workflow.executePoc(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectErrorMatches(ex ->
                            !(ex instanceof es.in2.issuer.backend.dome.domain.exception.ConflictingMigrationStateException))
                    .verify();
        }
    }

    @Nested
    @DisplayName("executeMigration — pre-conditions")
    class ExecuteMigrationPreConditions {

        @Test
        @DisplayName("no tenant in context — errors with IllegalStateException")
        void executeMigration_noTenant_errorsWithIllegalStateException() {
            // Act & Assert
            StepVerifier.create(workflow.executeMigration(LEGACY_KEY_ID))
                    .expectErrorMatches(ex -> ex instanceof IllegalStateException)
                    .verify();
        }

        @Test
        @DisplayName("no migration record — errors with ConflictingMigrationStateException")
        void executeMigration_noRecord_errorsWithConflicting() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID)).thenReturn(Mono.empty());

            // Act & Assert
            StepVerifier.create(
                    workflow.executeMigration(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectError(ConflictingMigrationStateException.class)
                    .verify();
        }

        @Test
        @DisplayName("PENDING state — errors with ConflictingMigrationStateException")
        void executeMigration_pendingState_errorsWithConflicting() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID))
                    .thenReturn(Mono.just(MigrationStatus.PENDING));

            // Act & Assert
            StepVerifier.create(
                    workflow.executeMigration(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectErrorMatches(ex ->
                            ex instanceof ConflictingMigrationStateException
                            && ex.getMessage().contains("PENDING"))
                    .verify();
        }

        @Test
        @DisplayName("MIGRATED state — errors with ConflictingMigrationStateException")
        void executeMigration_migratedState_errorsWithConflicting() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID))
                    .thenReturn(Mono.just(MigrationStatus.MIGRATED));

            // Act & Assert
            StepVerifier.create(
                    workflow.executeMigration(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectError(ConflictingMigrationStateException.class)
                    .verify();
        }
    }

    @Nested
    @DisplayName("executeRollback — pre-conditions")
    class ExecuteRollbackPreConditions {

        @Test
        @DisplayName("no tenant in context — errors with IllegalStateException")
        void executeRollback_noTenant_errorsWithIllegalStateException() {
            // Act & Assert
            StepVerifier.create(workflow.executeRollback(LEGACY_KEY_ID))
                    .expectErrorMatches(ex -> ex instanceof IllegalStateException)
                    .verify();
        }

        @Test
        @DisplayName("no migration record — errors with ConflictingMigrationStateException")
        void executeRollback_noRecord_errorsWithConflicting() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID)).thenReturn(Mono.empty());

            // Act & Assert
            StepVerifier.create(
                    workflow.executeRollback(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectError(ConflictingMigrationStateException.class)
                    .verify();
        }

        @Test
        @DisplayName("MIGRATED state — cannot roll back, errors with ConflictingMigrationStateException")
        void executeRollback_migratedState_errorsWithConflicting() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID))
                    .thenReturn(Mono.just(MigrationStatus.MIGRATED));

            // Act & Assert
            StepVerifier.create(
                    workflow.executeRollback(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectErrorMatches(ex ->
                            ex instanceof ConflictingMigrationStateException
                            && ex.getMessage().contains("MIGRATED"))
                    .verify();
        }

        @Test
        @DisplayName("PENDING state — cannot roll back from non-POC_OK, errors with ConflictingMigrationStateException")
        void executeRollback_pendingState_errorsWithConflicting() {
            // Arrange
            when(stateService.currentStatus(LEGACY_KEY_ID))
                    .thenReturn(Mono.just(MigrationStatus.PENDING));

            // Act & Assert
            StepVerifier.create(
                    workflow.executeRollback(LEGACY_KEY_ID)
                            .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                    .expectError(ConflictingMigrationStateException.class)
                    .verify();
        }
    }
}

