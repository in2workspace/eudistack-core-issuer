package es.in2.issuer.backend.dome.domain.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Key-migration domain exceptions")
class DomainExceptionsTest {

    @Test
    @DisplayName("HashMismatchException(String) — stores message")
    void hashMismatch_messageConstructor_storesMessage() {
        var ex = new HashMismatchException("key material mismatch");

        assertThat(ex.getMessage()).isEqualTo("key material mismatch");
        assertThat(ex.getCause()).isNull();
    }

    @Test
    @DisplayName("HashMismatchException(String, Throwable) — stores message and cause")
    void hashMismatch_messageAndCauseConstructor_storesMessageAndCause() {
        var cause = new RuntimeException("root cause");
        var ex = new HashMismatchException("key material mismatch", cause);

        assertThat(ex.getMessage()).isEqualTo("key material mismatch");
        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("HashMismatchException — is a RuntimeException")
    void hashMismatch_isRuntimeException() {
        assertThat(new HashMismatchException("x")).isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("ConflictingMigrationStateException(String) — stores message")
    void conflictingState_messageConstructor_storesMessage() {
        var ex = new ConflictingMigrationStateException("cannot transition");

        assertThat(ex.getMessage()).isEqualTo("cannot transition");
        assertThat(ex.getCause()).isNull();
    }

    @Test
    @DisplayName("ConflictingMigrationStateException(String, Throwable) — stores message and cause")
    void conflictingState_messageAndCauseConstructor_storesMessageAndCause() {
        var cause = new IllegalStateException("inner");
        var ex = new ConflictingMigrationStateException("cannot transition", cause);

        assertThat(ex.getMessage()).isEqualTo("cannot transition");
        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("ConflictingMigrationStateException — is a RuntimeException")
    void conflictingState_isRuntimeException() {
        assertThat(new ConflictingMigrationStateException("x")).isInstanceOf(RuntimeException.class);
    }
}

