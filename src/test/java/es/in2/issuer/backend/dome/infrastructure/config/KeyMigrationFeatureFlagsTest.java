package es.in2.issuer.backend.dome.infrastructure.config;

import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("KeyMigrationProperties — feature flags")
class KeyMigrationFeatureFlagsTest {

    private ApplicationContextRunner context;

    @BeforeEach
    void setUp() {
        context = new ApplicationContextRunner()
                .withUserConfiguration(KeyMigrationConfiguration.class);
    }

    @Test
    @DisplayName("planAEnabled — when no env var set — defaults to false")
    void planAEnabled_WhenNoEnvVarSet_DefaultsFalse() {
        // Arrange + Act + Assert
        context.run(ctx -> {
            KeyMigrationProperties props = ctx.getBean(KeyMigrationProperties.class);
            assertThat(props.planAEnabled()).isFalse();
        });
    }

    @Test
    @DisplayName("planAEnabled — when property set to true — returns true")
    void planAEnabled_WhenPropertySetToTrue_ReturnsTrue() {
        // Act + Assert
        context.withPropertyValues("issuer.dome.key-migration.plan-a-enabled=true")
                .run(ctx -> {
                    KeyMigrationProperties props = ctx.getBean(KeyMigrationProperties.class);
                    assertThat(props.planAEnabled()).isTrue();
                });
    }

    @Test
    @DisplayName("legacyKeyId — when not set — defaults to empty string")
    void legacyKeyId_WhenNotSet_DefaultsEmpty() {
        // Act + Assert
        context.run(ctx -> {
            KeyMigrationProperties props = ctx.getBean(KeyMigrationProperties.class);
            assertThat(props.legacyKeyId()).isEmpty();
        });
    }
}

