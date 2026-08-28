package es.in2.issuer.backend.shared.infrastructure.config.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static es.in2.issuer.backend.shared.infrastructure.config.logging.MaskingPatternLayout.REPLACEMENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MaskingOpenTelemetryAppenderTest {

    private static final String JWT_SAMPLE =
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // ─── getFormattedMessage() / getMessage() ─────────────────────────────────

    @Test
    void mask_FormattedMessageWithJwt_MasksJwt() {
        // Arrange
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getFormattedMessage()).thenReturn("Validating token: " + JWT_SAMPLE);

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getFormattedMessage())
                .contains(REPLACEMENT)
                .doesNotContain(JWT_SAMPLE);
    }

    @Test
    void mask_MessageTemplateWithEmail_MasksEmail() {
        // Arrange
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMessage()).thenReturn("Notifying admin@empresa.com");

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getMessage())
                .contains(REPLACEMENT)
                .doesNotContain("admin@empresa.com");
    }

    // ─── getArgumentArray() ─────────────────────────────────────────────────────

    @Test
    void mask_ArgumentArray_IsNulledOutSoOriginalCannotBeReRendered() {
        // Arrange
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getArgumentArray()).thenReturn(new Object[]{"admin@empresa.com"});

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getArgumentArray()).isNull();
    }

    // ─── getMDCPropertyMap() / getMdc() ─────────────────────────────────────────

    @Test
    void mask_MdcPropertyMapWithEmailValue_MasksValueKeepsKey() {
        // Arrange – audit.userId is whitelisted into the JSON console appender's MDC and
        // can carry an email; the OTLP appender must redact it just the same.
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMDCPropertyMap()).thenReturn(Map.of("audit.userId", "admin@empresa.com"));

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);
        Map<String, String> maskedMdc = masked.getMDCPropertyMap();

        // Assert
        assertThat(maskedMdc)
                .containsKey("audit.userId")
                .containsEntry("audit.userId", REPLACEMENT);
    }

    @Test
    void mask_MdcPropertyMapWithNonSensitiveValue_LeavesValueUnchanged() {
        // Arrange
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMDCPropertyMap()).thenReturn(Map.of("tenantDomain", "sandbox"));

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getMDCPropertyMap()).containsEntry("tenantDomain", "sandbox");
    }

    @Test
    void mask_DeprecatedGetMdcWithSecretValue_MasksValue() {
        // Arrange
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMdc()).thenReturn(Map.of("client_secret", "oauth2ClientSecret"));

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getMdc()).containsEntry("client_secret", REPLACEMENT);
    }

    // ─── Unmasked passthrough ────────────────────────────────────────────────────

    @Test
    void mask_LoggerName_IsForwardedUnchanged() {
        // Arrange
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getLoggerName()).thenReturn("es.in2.issuer.backend.issuance.SomeService");

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getLoggerName()).isEqualTo("es.in2.issuer.backend.issuance.SomeService");
    }
}
