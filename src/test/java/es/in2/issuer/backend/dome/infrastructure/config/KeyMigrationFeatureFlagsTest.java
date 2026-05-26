package es.in2.issuer.backend.dome.infrastructure.config;

import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("KeyMigrationProperties — feature flag defaults (AC-05)")
class KeyMigrationFeatureFlagsTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(KeyMigrationConfiguration.class);

    @Test
    @DisplayName("plan A flag defaults to false when no environment variable is set")
    void planAEnabled_WhenNoEnvVarSet_DefaultsFalse() {
        // Arrange
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
        // Arrange
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

