package es.in2.issuer.backend.shared.domain.model.enums;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class BindingTypeTest {

    @ParameterizedTest
    @CsvSource({"key, KEY, true", "none, NONE, true", "claim, CLAIM, false", "biometric, BIOMETRIC, false"})
    void fromValue_parsesTheRegistryValues_andOnlyKeyAndNoneAreSupported(String value, BindingType expected,
                                                                          boolean supported) {
        assertThat(BindingType.fromValue(value)).contains(expected);
        assertThat(expected.isSupported()).isEqualTo(supported);
    }

    @Test
    void fromValue_ofAnythingElse_isEmpty() {
        assertThat(BindingType.fromValue("x509")).isEmpty();
        assertThat(BindingType.fromValue("KEY")).isEmpty();
        assertThat(BindingType.fromValue(null)).isEmpty();
    }
}
