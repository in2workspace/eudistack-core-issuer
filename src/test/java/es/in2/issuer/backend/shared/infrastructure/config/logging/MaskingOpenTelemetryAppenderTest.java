package es.in2.issuer.backend.shared.infrastructure.config.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.infrastructure.config.logging.MaskingPatternLayout.REPLACEMENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
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
    void mask_ArgumentArray_IsEmptiedSoOriginalCannotBeReRendered() {
        // Arrange
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getArgumentArray()).thenReturn(new Object[]{"admin@empresa.com"});

        // Act
        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);

        // Assert
        assertThat(masked.getArgumentArray()).isEmpty();
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

    @Test
    void mask_NullMdc_ReturnsEmptyMap() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        when(source.getMDCPropertyMap()).thenReturn(null);

        assertThat(MaskingOpenTelemetryAppender.mask(source).getMDCPropertyMap()).isEmpty();
    }

    @Test
    void mask_EveryOtherAccessor_IsForwardedUnchanged() {
        ILoggingEvent source = mock(ILoggingEvent.class);
        Instant now = Instant.now();
        when(source.getThreadName()).thenReturn("reactor-http-nio-3");
        when(source.getLevel()).thenReturn(Level.INFO);
        when(source.getTimeStamp()).thenReturn(now.toEpochMilli());
        when(source.getInstant()).thenReturn(now);
        when(source.getNanoseconds()).thenReturn(42);
        when(source.getSequenceNumber()).thenReturn(7L);
        when(source.hasCallerData()).thenReturn(true);
        when(source.getMarkerList()).thenReturn(List.of());
        when(source.getKeyValuePairs()).thenReturn(List.of());

        ILoggingEvent masked = MaskingOpenTelemetryAppender.mask(source);
        masked.prepareForDeferredProcessing();

        assertThat(masked.getThreadName()).isEqualTo("reactor-http-nio-3");
        assertThat(masked.getLevel()).isEqualTo(Level.INFO);
        assertThat(masked.getTimeStamp()).isEqualTo(now.toEpochMilli());
        assertThat(masked.getInstant()).isEqualTo(now);
        assertThat(masked.getNanoseconds()).isEqualTo(42);
        assertThat(masked.getSequenceNumber()).isEqualTo(7L);
        assertThat(masked.hasCallerData()).isTrue();
        assertThat(masked.getMarkerList()).isEmpty();
        assertThat(masked.getKeyValuePairs()).isEmpty();
        assertThat(masked.getLoggerContextVO()).isNull();
        assertThat(masked.getThrowableProxy()).isNull();
        assertThat(masked.getCallerData()).isNull();
        verify(source).prepareForDeferredProcessing();
    }
}
