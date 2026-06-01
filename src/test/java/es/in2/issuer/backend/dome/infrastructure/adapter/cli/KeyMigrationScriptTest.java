package es.in2.issuer.backend.dome.infrastructure.adapter.cli;

import es.in2.issuer.backend.dome.application.workflow.KeyMigrationWorkflow;
import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("KeyMigrationScript — CLI shell commands")
class KeyMigrationScriptTest {

    @Mock
    private KeyMigrationWorkflow keyMigrationWorkflow;
    @Mock
    private CliOperatorAuthFilter filter;
    @Mock
    private KeyMigrationProperties properties;

    @InjectMocks
    private KeyMigrationScript script;

    @BeforeEach
    void configureHappyPathDefaults() {
        when(properties.legacyKeyId()).thenReturn("my-legacy-key");
        lenient().when(properties.tenantDomain()).thenReturn("localhost");
    }


    @Test
    @DisplayName("poc — when legacyKeyId is null — throws IllegalStateException before workflow call")
    void poc_whenLegacyKeyIdNull_throwsBeforeWorkflowCall() {
        when(properties.legacyKeyId()).thenReturn(null);

        assertThatThrownBy(() -> script.poc("op-123"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("issuer.dome.key-migration.legacy-key-id");
        verifyNoInteractions(keyMigrationWorkflow);
    }

    @Test
    @DisplayName("poc — when legacyKeyId is blank — throws IllegalStateException before workflow call")
    void poc_whenLegacyKeyIdBlank_throwsBeforeWorkflowCall() {
        when(properties.legacyKeyId()).thenReturn("  ");

        assertThatThrownBy(() -> script.poc("op-123"))
                .isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(keyMigrationWorkflow);
    }

    @Test
    @DisplayName("poc — when valid — delegates to workflow.executePoc")
    void poc_whenValid_delegatesToWorkflow() {
        when(keyMigrationWorkflow.executePoc("my-legacy-key")).thenReturn(Mono.empty());

        assertThatNoException().isThrownBy(() -> script.poc("op-123456"));
        verify(keyMigrationWorkflow).executePoc("my-legacy-key");
    }

    @Test
    @DisplayName("migrate — when legacyKeyId is null — throws IllegalStateException before workflow call")
    void migrate_whenLegacyKeyIdNull_throwsBeforeWorkflowCall() {
        when(properties.legacyKeyId()).thenReturn(null);

        assertThatThrownBy(() -> script.migrate("op-123"))
                .isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(keyMigrationWorkflow);
    }

    @Test
    @DisplayName("migrate — when valid — delegates to workflow.executeMigration")
    void migrate_whenValid_delegatesToWorkflow() {
        when(keyMigrationWorkflow.executeMigration("my-legacy-key")).thenReturn(Mono.empty());

        assertThatNoException().isThrownBy(() -> script.migrate("op-123456"));
        verify(keyMigrationWorkflow).executeMigration("my-legacy-key");
    }

    @Test
    @DisplayName("rollback — when legacyKeyId is null — throws IllegalStateException before workflow call")
    void rollback_whenLegacyKeyIdNull_throwsBeforeWorkflowCall() {
        when(properties.legacyKeyId()).thenReturn(null);

        assertThatThrownBy(() -> script.rollback("op-123"))
                .isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(keyMigrationWorkflow);
    }

    @Test
    @DisplayName("rollback — when valid — delegates to workflow.executeRollback")
    void rollback_whenValid_delegatesToWorkflow() {
        when(keyMigrationWorkflow.executeRollback("my-legacy-key")).thenReturn(Mono.empty());

        assertThatNoException().isThrownBy(() -> script.rollback("op-123456"));
        verify(keyMigrationWorkflow).executeRollback("my-legacy-key");
    }
}


