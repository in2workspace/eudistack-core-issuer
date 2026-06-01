package es.in2.issuer.backend.dome.infrastructure.adapter.cli;

import es.in2.issuer.backend.dome.infrastructure.config.properties.KeyMigrationProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("CliOperatorAuthFilter — pre-flight operator authentication")
class CliOperatorAuthFilterTest {

    @Mock
    private KeyMigrationProperties properties;

    @InjectMocks
    private CliOperatorAuthFilter filter;

    @Test
    @DisplayName("validatePlanA — when operatorId is null — throws IllegalStateException")
    void validatePlanA_whenOperatorIdNull_throwsIllegalStateException() {
        assertThatThrownBy(() -> filter.validatePlanA(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("operatorId must not be blank");
    }

    @Test
    @DisplayName("validatePlanA — when operatorId is blank — throws IllegalStateException")
    void validatePlanA_whenOperatorIdBlank_throwsIllegalStateException() {
        assertThatThrownBy(() -> filter.validatePlanA("   "))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("operatorId must not be blank");
    }

    @Test
    @DisplayName("validatePlanA — when planAEnabled is false — throws IllegalStateException")
    void validatePlanA_whenPlanADisabled_throwsIllegalStateException() {
        when(properties.planAEnabled()).thenReturn(false);

        assertThatThrownBy(() -> filter.validatePlanA("op-12345"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Plan A not enabled");
    }

    @Test
    @DisplayName("validatePlanA — when planAEnabled and valid operatorId — does not throw")
    void validatePlanA_whenPlanAEnabledAndValidOperatorId_doesNotThrow() {
        when(properties.planAEnabled()).thenReturn(true);

        assertThatNoException().isThrownBy(() -> filter.validatePlanA("op-12345678"));
    }

    @Test
    @DisplayName("validatePlanA — when operatorId has 4 or fewer chars — masks fully but passes if planA enabled")
    void validatePlanA_whenShortOperatorId_masksAndPasses() {
        when(properties.planAEnabled()).thenReturn(true);
        assertThatNoException().isThrownBy(() -> filter.validatePlanA("ab"));
    }
}

