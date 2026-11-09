package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.statuslist.domain.model.RevocationRequestViolation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class RevocationRequestValidatorTest {

    private static final String ID = "0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90";

    @Test
    void validate_acceptsAReasonOfExactly280Characters() {
        assertThat(RevocationRequestValidator.validate(ID, "x".repeat(280))).isEmpty();
    }

    @Test
    void validate_rejectsAReasonOf281Characters() {
        assertThat(RevocationRequestValidator.validate(ID, "x".repeat(281)))
                .containsExactly(new RevocationRequestViolation("reason", "must be at most 280 characters"));
    }

    @Test
    void validate_countsAnEmojiAsOneCharacter() {
        assertThat(RevocationRequestValidator.validate(ID, "😀".repeat(280))).isEmpty();
        assertThat(RevocationRequestValidator.validate(ID, "😀".repeat(281))).hasSize(1);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   ", "\n\t", "\u0001\u0002"})
    void validate_requiresAReasonWithContent(String reason) {
        assertThat(RevocationRequestValidator.validate(ID, reason))
                .containsExactly(new RevocationRequestViolation("reason", "is required"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-uuid", "1-1-1-1-1", "0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90\nAUDIT"})
    void validate_requiresACanonicalUuid(String id) {
        assertThat(RevocationRequestValidator.validate(id, "Baja"))
                .containsExactly(new RevocationRequestViolation("id", "must be a UUID"));
    }

    @Test
    void validate_reportsEveryField() {
        assertThat(RevocationRequestValidator.validate("nope", null)).hasSize(2);
    }
}
