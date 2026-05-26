package es.in2.issuer.backend.dome.domain.model.keymigration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("MigrationStatus — state machine transitions")
class MigrationStatusTest {


    @ParameterizedTest(name = "{0} -> {1} should be allowed")
    @CsvSource({
            "PENDING,       POC_OK",
            "PENDING,       POC_FAILED",
            "PENDING,       FAILED",
            "POC_OK,        PLAN_A_OK",
            "POC_OK,        PLAN_B_REISSUE",
            "POC_OK,        FAILED",
            "POC_FAILED,    PLAN_B_REISSUE",
            "POC_FAILED,    FAILED",
            "PLAN_A_OK,     ROLLED_BACK",
            "PLAN_B_REISSUE,PLAN_B_PARTIAL",
            "PLAN_B_REISSUE,FAILED",
            "FAILED,        PENDING"
    })
    @DisplayName("canTransitionTo_ValidTransition_ReturnsTrue")
    void canTransitionTo_ValidTransition_ReturnsTrue(String from, String to) {
        // Arrange
        MigrationStatus source = MigrationStatus.valueOf(from.trim());
        MigrationStatus target = MigrationStatus.valueOf(to.trim());

        // Act
        boolean result = source.canTransitionTo(target);

        // Assert
        assertThat(result).isTrue();
    }


    @ParameterizedTest(name = "{0} -> {1} should NOT be allowed")
    @CsvSource({
            "PENDING,        PLAN_A_OK",       // skipping POC step
            "PLAN_A_OK,      PLAN_B_REISSUE",  // terminal state ES-04
            "PLAN_B_REISSUE, PENDING",          // R-143-6: no revert to PENDING
            "ROLLED_BACK,    PENDING",           // terminal state
            "PLAN_B_PARTIAL, FAILED",            // no outgoing transitions
            "POC_FAILED,     PLAN_A_OK"          // must go through PLAN_B_REISSUE
    })
    @DisplayName("canTransitionTo_InvalidTransition_ReturnsFalse")
    void canTransitionTo_InvalidTransition_ReturnsFalse(String from, String to) {
        // Arrange
        MigrationStatus source = MigrationStatus.valueOf(from.trim());
        MigrationStatus target = MigrationStatus.valueOf(to.trim());

        // Act
        boolean result = source.canTransitionTo(target);

        // Assert
        assertThat(result).isFalse();
    }
}

