package es.in2.issuer.backend.dome.infrastructure.config;

import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies AC-05: both feature flags default to {@code false} when no environment
 * variable is configured, guaranteeing a deploy-safe behaviour out of the box.
 */
@DisplayName("KeyMigrationProperties — feature flag defaults (AC-05)")
class KeyMigrationFeatureFlagsTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(KeyMigrationConfiguration.class);

    @Test
    @DisplayName("plan A flag defaults to false when no environment variable is set")
    void planAEnabled_WhenNoEnvVarSet_DefaultsFalse() {
        // Arrange — no properties set, only @DefaultValue annotations in effect
        contextRunner.run(ctx -> {
            // Act
            KeyMigrationProperties props = ctx.getBean(KeyMigrationProperties.class);

            // Assert
            assertThat(props.planAEnabled())
                    .as("planAEnabled must default to false for deploy-safety (AC-05)")
                    .isFalse();
        });
    }

    @Test
    @DisplayName("plan B flag defaults to false when no environment variable is set")
    void planBEnabled_WhenNoEnvVarSet_DefaultsFalse() {
        // Arrange — no properties set, only @DefaultValue annotations in effect
        contextRunner.run(ctx -> {
            // Act
            KeyMigrationProperties props = ctx.getBean(KeyMigrationProperties.class);

            // Assert
            assertThat(props.planBEnabled())
                    .as("planBEnabled must default to false for deploy-safety (AC-05)")
                    .isFalse();
        });
    }

    @Test
    @DisplayName("plan A flag returns true when the property is explicitly set to true")
    void planAEnabled_WhenPropertySetToTrue_ReturnsTrue() {
        // Arrange
        contextRunner
                .withPropertyValues("issuer.dome.key-migration.plan-a-enabled=true")
                .run(ctx -> {
                    // Act
                    KeyMigrationProperties props = ctx.getBean(KeyMigrationProperties.class);

                    // Assert
                    assertThat(props.planAEnabled())
                            .as("planAEnabled must be true when explicitly configured")
                            .isTrue();
                });
    }
}

