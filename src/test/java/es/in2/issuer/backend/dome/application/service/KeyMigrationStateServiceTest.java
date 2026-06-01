package es.in2.issuer.backend.dome.application.service;

import es.in2.issuer.backend.dome.domain.model.keymigration.DomeKeyMigration;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import es.in2.issuer.backend.dome.domain.spi.DomeKeyMigrationRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("KeyMigrationStateService — state machine transitions")
class KeyMigrationStateServiceTest {

    @Mock
    private DomeKeyMigrationRepositoryPort repository;

    @InjectMocks
    private KeyMigrationStateService service;

    private static final String LEGACY_KEY_ID = "key-abc-123";
    private static final LegacyKeyId LEGACY_KEY = new LegacyKeyId(LEGACY_KEY_ID);

    @Nested
    @DisplayName("transitionTo")
    class TransitionTo {

        @Test
        @DisplayName("no existing record — creates PENDING and then saves with target status")
        void transitionTo_noRecord_createsPendingThenTransitions() {
            // Arrange
            when(repository.findByLegacyKeyId(LEGACY_KEY)).thenReturn(Mono.empty());
            when(repository.save(any())).thenAnswer(inv -> Mono.just(inv.<DomeKeyMigration>getArgument(0)));

            // Act & Assert
            StepVerifier.create(service.transitionTo(LEGACY_KEY, MigrationStatus.POC_OK))
                    .assertNext(entity -> assertThat(entity.getMigrationStatus())
                            .isEqualTo(MigrationStatus.POC_OK.name()))
                    .verifyComplete();

            verify(repository, times(2)).save(any());
        }

        @Test
        @DisplayName("existing PENDING record — saves with POC_OK status")
        void transitionTo_existingPending_transitionsToPocock() {
            // Arrange
            DomeKeyMigration pending = DomeKeyMigration.builder()
                    .id(UUID.randomUUID())
                    .legacyKeyId(LEGACY_KEY_ID)
                    .migrationStatus(MigrationStatus.PENDING.name())
                    .build();

            when(repository.findByLegacyKeyId(LEGACY_KEY)).thenReturn(Mono.just(pending));
            when(repository.save(any())).thenReturn(Mono.just(pending));

            // Act & Assert
            StepVerifier.create(service.transitionTo(LEGACY_KEY, MigrationStatus.POC_OK))
                    .assertNext(entity -> assertThat(entity.getMigrationStatus())
                            .isEqualTo(MigrationStatus.POC_OK.name()))
                    .verifyComplete();

            verify(repository, times(1)).save(argThat(e ->
                    MigrationStatus.POC_OK.name().equals(e.getMigrationStatus())));
        }

        @Test
        @DisplayName("existing POC_OK record — saves with MIGRATED status")
        void transitionTo_existingPocOk_transitionsToMigrated() {
            // Arrange
            DomeKeyMigration pocOk = DomeKeyMigration.builder()
                    .id(UUID.randomUUID())
                    .legacyKeyId(LEGACY_KEY_ID)
                    .migrationStatus(MigrationStatus.POC_OK.name())
                    .build();

            when(repository.findByLegacyKeyId(LEGACY_KEY)).thenReturn(Mono.just(pocOk));
            when(repository.save(any())).thenReturn(Mono.just(pocOk));

            // Act & Assert
            StepVerifier.create(service.transitionTo(LEGACY_KEY, MigrationStatus.MIGRATED))
                    .assertNext(entity -> assertThat(entity.getMigrationStatus())
                            .isEqualTo(MigrationStatus.MIGRATED.name()))
                    .verifyComplete();
        }

        @Test
        @DisplayName("existing POC_OK record — saves with ROLLED_BACK status")
        void transitionTo_existingPocOk_transitionsToRolledBack() {
            // Arrange
            DomeKeyMigration pocOk = DomeKeyMigration.builder()
                    .id(UUID.randomUUID())
                    .legacyKeyId(LEGACY_KEY_ID)
                    .migrationStatus(MigrationStatus.POC_OK.name())
                    .build();

            when(repository.findByLegacyKeyId(LEGACY_KEY)).thenReturn(Mono.just(pocOk));
            when(repository.save(any())).thenReturn(Mono.just(pocOk));

            // Act & Assert
            StepVerifier.create(service.transitionTo(LEGACY_KEY, MigrationStatus.ROLLED_BACK))
                    .assertNext(entity -> assertThat(entity.getMigrationStatus())
                            .isEqualTo(MigrationStatus.ROLLED_BACK.name()))
                    .verifyComplete();
        }

        @Test
        @DisplayName("current status equals target — returns entity without saving again (idempotent)")
        void transitionTo_currentEqualsTarget_returnsWithoutSaving() {
            // Arrange
            DomeKeyMigration pocOk = DomeKeyMigration.builder()
                    .id(UUID.randomUUID())
                    .legacyKeyId(LEGACY_KEY_ID)
                    .migrationStatus(MigrationStatus.POC_OK.name())
                    .build();

            when(repository.findByLegacyKeyId(LEGACY_KEY)).thenReturn(Mono.just(pocOk));

            // Act & Assert
            StepVerifier.create(service.transitionTo(LEGACY_KEY, MigrationStatus.POC_OK))
                    .assertNext(entity -> assertThat(entity.getMigrationStatus())
                            .isEqualTo(MigrationStatus.POC_OK.name()))
                    .verifyComplete();

            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("invalid transition MIGRATED → PENDING — errors with IllegalStateException")
        void transitionTo_invalidTransition_errorsWithIllegalStateException() {
            // Arrange
            DomeKeyMigration migrated = DomeKeyMigration.builder()
                    .id(UUID.randomUUID())
                    .legacyKeyId(LEGACY_KEY_ID)
                    .migrationStatus(MigrationStatus.MIGRATED.name())
                    .build();

            when(repository.findByLegacyKeyId(LEGACY_KEY)).thenReturn(Mono.just(migrated));

            // Act & Assert
            StepVerifier.create(service.transitionTo(LEGACY_KEY, MigrationStatus.PENDING))
                    .expectErrorMatches(ex -> ex instanceof IllegalStateException
                            && ex.getMessage().contains("Invalid transition from MIGRATED to PENDING"))
                    .verify();

            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("invalid transition ROLLED_BACK → POC_OK — errors with IllegalStateException")
        void transitionTo_rolledBackToPocOk_errorsWithIllegalStateException() {
            // Arrange
            DomeKeyMigration rolledBack = DomeKeyMigration.builder()
                    .id(UUID.randomUUID())
                    .legacyKeyId(LEGACY_KEY_ID)
                    .migrationStatus(MigrationStatus.ROLLED_BACK.name())
                    .build();

            when(repository.findByLegacyKeyId(LEGACY_KEY)).thenReturn(Mono.just(rolledBack));

            // Act & Assert
            StepVerifier.create(service.transitionTo(LEGACY_KEY, MigrationStatus.POC_OK))
                    .expectErrorMatches(ex -> ex instanceof IllegalStateException
                            && ex.getMessage().contains("Invalid transition"))
                    .verify();
        }

        @Test
        @DisplayName("FAILED → PENDING — saves with PENDING status")
        void transitionTo_failedToPending_succeeds() {
            // Arrange
            DomeKeyMigration failed = DomeKeyMigration.builder()
                    .id(UUID.randomUUID())
                    .legacyKeyId(LEGACY_KEY_ID)
                    .migrationStatus(MigrationStatus.FAILED.name())
                    .build();

            when(repository.findByLegacyKeyId(LEGACY_KEY)).thenReturn(Mono.just(failed));
            when(repository.save(any())).thenReturn(Mono.just(failed));

            // Act & Assert
            StepVerifier.create(service.transitionTo(LEGACY_KEY, MigrationStatus.PENDING))
                    .assertNext(entity -> assertThat(entity.getMigrationStatus())
                            .isEqualTo(MigrationStatus.PENDING.name()))
                    .verifyComplete();
        }
    }

    @Nested
    @DisplayName("currentStatus")
    class CurrentStatus {

        @Test
        @DisplayName("existing record — returns mapped MigrationStatus")
        void currentStatus_existingRecord_returnsMappedStatus() {
            // Arrange
            DomeKeyMigration pocOk = DomeKeyMigration.builder()
                    .legacyKeyId(LEGACY_KEY_ID)
                    .migrationStatus(MigrationStatus.POC_OK.name())
                    .build();

            when(repository.findByLegacyKeyId(new LegacyKeyId(LEGACY_KEY_ID)))
                    .thenReturn(Mono.just(pocOk));

            // Act & Assert
            StepVerifier.create(service.currentStatus(LEGACY_KEY_ID))
                    .expectNext(MigrationStatus.POC_OK)
                    .verifyComplete();
        }

        @Test
        @DisplayName("no record — returns empty Mono")
        void currentStatus_noRecord_returnsEmpty() {
            // Arrange
            when(repository.findByLegacyKeyId(new LegacyKeyId(LEGACY_KEY_ID)))
                    .thenReturn(Mono.empty());

            // Act & Assert
            StepVerifier.create(service.currentStatus(LEGACY_KEY_ID))
                    .verifyComplete();
        }

        @Test
        @DisplayName("MIGRATED record — returns MIGRATED status")
        void currentStatus_migratedRecord_returnsMigrated() {
            // Arrange
            DomeKeyMigration migrated = DomeKeyMigration.builder()
                    .legacyKeyId(LEGACY_KEY_ID)
                    .migrationStatus(MigrationStatus.MIGRATED.name())
                    .build();

            when(repository.findByLegacyKeyId(new LegacyKeyId(LEGACY_KEY_ID)))
                    .thenReturn(Mono.just(migrated));

            // Act & Assert
            StepVerifier.create(service.currentStatus(LEGACY_KEY_ID))
                    .expectNext(MigrationStatus.MIGRATED)
                    .verifyComplete();
        }
    }
}
