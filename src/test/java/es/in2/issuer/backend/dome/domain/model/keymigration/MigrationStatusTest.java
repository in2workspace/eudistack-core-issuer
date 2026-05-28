package es.in2.issuer.backend.dome.domain.model.keymigration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("MigrationStatus — state machine transitions")
class MigrationStatusTest {

    @ParameterizedTest(name = "{0} → {1} should be valid")
    @CsvSource({
            "PENDING,    POC_OK",
            "PENDING,    FAILED",
            "POC_OK,     MIGRATED",
            "POC_OK,     ROLLED_BACK",
            "POC_OK,     FAILED",
            "FAILED,     PENDING"
    })
    @DisplayName("canTransitionTo — given valid transitions — returns true")
    void canTransitionTo_ValidTransition_ReturnsTrue(String from, String to) {
        // Arrange
        MigrationStatus fromStatus = MigrationStatus.valueOf(from.trim());
        MigrationStatus toStatus = MigrationStatus.valueOf(to.trim());

        // Act
        boolean result = fromStatus.canTransitionTo(toStatus);

        // Assert
        assertThat(result).isTrue();
    }

    @ParameterizedTest(name = "{0} → {1} should be invalid")
    @CsvSource({
            "PENDING,      MIGRATED",
            "PENDING,      ROLLED_BACK",
            "MIGRATED,     PENDING",
            "MIGRATED,     POC_OK",
            "MIGRATED,     FAILED",
            "MIGRATED,     ROLLED_BACK",
            "ROLLED_BACK,  PENDING",
            "ROLLED_BACK,  MIGRATED",
            "FAILED,       POC_OK",
            "FAILED,       MIGRATED"
    })
    @DisplayName("canTransitionTo — given invalid transitions — returns false")
    void canTransitionTo_InvalidTransition_ReturnsFalse(String from, String to) {
        // Arrange
        MigrationStatus fromStatus = MigrationStatus.valueOf(from.trim());
        MigrationStatus toStatus = MigrationStatus.valueOf(to.trim());

        // Act
        boolean result = fromStatus.canTransitionTo(toStatus);

        // Assert
        assertThat(result).isFalse();
    }
}

