package es.in2.issuer.backend.dome.domain.model.keymigration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("LegacyKeyId — compact record with validation")
class LegacyKeyIdTest {

    @Test
    @DisplayName("constructor — valid value — stores it")
    void constructor_validValue_storesIt() {
        var id = new LegacyKeyId("my-key-id");
        assertThat(id.value()).isEqualTo("my-key-id");
    }

    @Test
    @DisplayName("constructor — null value — throws IllegalArgumentException")
    void constructor_nullValue_throwsIllegalArgumentException() {
        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new LegacyKeyId(null)
        );
    }

    @Test
    @DisplayName("constructor — blank value — throws IllegalArgumentException")
    void constructor_blankValue_throwsIllegalArgumentException() {
        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new LegacyKeyId("   ")
        );
    }

    @Test
    @DisplayName("constructor — value over 255 chars — throws IllegalArgumentException")
    void constructor_valueTooLong_throwsIllegalArgumentException() {
        String tooLong = "a".repeat(256);
        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new LegacyKeyId(tooLong)
        );
    }

    @Test
    @DisplayName("constructor — value exactly 255 chars — succeeds")
    void constructor_value255Chars_succeeds() {
        String exactly255 = "a".repeat(255);
        var id = new LegacyKeyId(exactly255);
        assertThat(id.value()).hasSize(255);
    }

    @Test
    @DisplayName("equality — same value — records are equal")
    void equality_sameValue_recordsAreEqual() {
        assertThat(new LegacyKeyId("key-1")).isEqualTo(new LegacyKeyId("key-1"));
    }
}

