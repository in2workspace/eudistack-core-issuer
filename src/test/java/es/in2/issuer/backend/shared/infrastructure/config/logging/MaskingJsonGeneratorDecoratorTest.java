package es.in2.issuer.backend.shared.infrastructure.config.logging;

import com.fasterxml.jackson.core.JsonStreamContext;
import net.logstash.logback.mask.ValueMasker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


import static es.in2.issuer.backend.shared.infrastructure.config.logging.MaskingPatternLayout.REPLACEMENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;

class MaskingJsonGeneratorDecoratorTest {

    private static final String JWT_SAMPLE =
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private ValueMasker piiValueMasker;

    @BeforeEach
    void setUp() {
        // Arrange (shared): obtain masker via package-private factory – no reflection needed
        piiValueMasker = MaskingJsonGeneratorDecorator.newPiiValueMasker();
    }

    // ─── Constructor ──────────────────────────────────────────────────────────

    @Test
    void constructor_WhenInstantiated_DoesNotThrow() {
        // Arrange – (none)

        // Act + Assert
        assertThatCode(MaskingJsonGeneratorDecorator::new).doesNotThrowAnyException();
    }


    // ─── PiiValueMasker – non-String values ──────────────────────────────────

    @Test
    void piiValueMasker_NullValue_ReturnsNull() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);

        // Act
        Object result = piiValueMasker.mask(context, null);

        // Assert
        assertThat(result).isNull();
    }

    @Test
    void piiValueMasker_IntegerValue_ReturnsNull() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);

        // Act
        Object result = piiValueMasker.mask(context, 42);

        // Assert
        assertThat(result).isNull();
    }

    @Test
    void piiValueMasker_BooleanValue_ReturnsNull() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);

        // Act
        Object result = piiValueMasker.mask(context, true);

        // Assert
        assertThat(result).isNull();
    }

    // ─── PiiValueMasker – unchanged strings (no sensitive data → null) ────────

    @Test
    void piiValueMasker_StringWithNoSensitiveData_ReturnsNull() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);
        String plainValue = "Application started on port 8080";

        // Act
        Object result = piiValueMasker.mask(context, plainValue);

        // Assert
        assertThat(result).isNull();
    }

    @Test
    void piiValueMasker_StringWithUuid_ReturnsNull() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);
        String uuidValue = "550e8400-e29b-41d4-a716-446655440000";

        // Act
        Object result = piiValueMasker.mask(context, uuidValue);

        // Assert
        assertThat(result).isNull();
    }

    // ─── PiiValueMasker – sensitive strings → returns masked value ───────────

    @Test
    void piiValueMasker_StringWithEmail_ReturnsMaskedString() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);
        String email = "user@example.com";

        // Act
        Object result = piiValueMasker.mask(context, email);

        // Assert
        assertThat(result)
                .isInstanceOf(String.class)
                .isEqualTo(REPLACEMENT);
    }

    @Test
    void piiValueMasker_StringWithJwt_ReturnsMaskedString() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);

        // Act
        Object result = piiValueMasker.mask(context, JWT_SAMPLE);

        // Assert
        assertThat(result)
                .isInstanceOf(String.class)
                .isEqualTo(REPLACEMENT);
    }

    @Test
    void piiValueMasker_StringWithBearerToken_ReturnsMaskedString() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);
        String bearerHeader = "Bearer someOpaqueTokenValue";

        // Act
        Object result = piiValueMasker.mask(context, bearerHeader);

        // Assert
        assertThat(result)
                .isInstanceOf(String.class)
                .asString()
                .contains("Bearer " + REPLACEMENT)
                .doesNotContain("someOpaqueTokenValue");
    }

    @Test
    void piiValueMasker_StringWithPassword_ReturnsMaskedString() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);
        String passwordField = "password:SuperSecret123!";

        // Act
        Object result = piiValueMasker.mask(context, passwordField);

        // Assert
        assertThat(result)
                .isInstanceOf(String.class)
                .asString()
                .contains(REPLACEMENT)
                .doesNotContain("SuperSecret123!");
    }

    @Test
    void piiValueMasker_StringWithAccessToken_ReturnsMaskedString() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);
        String tokenEntry = "access_token:theActualTokenValue";

        // Act
        Object result = piiValueMasker.mask(context, tokenEntry);

        // Assert
        assertThat(result)
                .isInstanceOf(String.class)
                .asString()
                .contains(REPLACEMENT)
                .doesNotContain("theActualTokenValue");
    }

    @Test
    void piiValueMasker_StringWithEmbeddedEmailInSentence_ReturnsMaskedString() {
        // Arrange
        JsonStreamContext context = mock(JsonStreamContext.class);
        String logLine = "User admin@empresa.com authenticated with token " + JWT_SAMPLE;

        // Act
        Object result = piiValueMasker.mask(context, logLine);

        // Assert
        assertThat(result)
                .isInstanceOf(String.class)
                .asString()
                .contains(REPLACEMENT)
                .doesNotContain("admin@empresa.com")
                .doesNotContain(JWT_SAMPLE);
    }

    // ─── PiiValueMasker – context is irrelevant ───────────────────────────────

    @Test
    void piiValueMasker_NullContext_StillMasksEmailValue() {
        // Arrange
        // JsonStreamContext is intentionally null — PiiValueMasker only uses the value
        String email = "contact@domain.org";

        // Act
        Object result = piiValueMasker.mask(null, email);

        // Assert
        assertThat(result)
                .isInstanceOf(String.class)
                .isEqualTo(REPLACEMENT);
    }
}


