package es.in2.issuer.backend.shared.infrastructure.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.DeliveryTrace;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditServiceImplTest {

    private static final String TENANT_ID = "sandbox";
    private static final String PROCESS_ID = "process-123";

    private final AuditServiceImpl auditService = new AuditServiceImpl();
    private ListAppender<ILoggingEvent> auditAppender;

    @BeforeEach
    void attachAuditAppender() {
        Logger auditLogger = (Logger) LoggerFactory.getLogger("AUDIT");
        auditAppender = new ListAppender<>();
        auditAppender.start();
        auditLogger.addAppender(auditAppender);
    }

    @AfterEach
    void detachAuditAppender() {
        Logger auditLogger = (Logger) LoggerFactory.getLogger("AUDIT");
        auditLogger.detachAppender(auditAppender);
        auditAppender.stop();
    }

    @Test
    void auditDelivery_withAllModesDelivered_emitsInfoSeverityWithExpectedFields() {
        // Given (AC-01/AC-04)
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID, Set.of(DeliveryResult.delivered("direct")));

        // When
        auditService.auditDelivery(trace);

        // Then
        assertEquals(1, auditAppender.list.size());
        ILoggingEvent event = auditAppender.list.get(0);
        assertEquals(Level.INFO, event.getLevel());
        String message = event.getFormattedMessage();
        assertTrue(message.contains("event=credential.delivered"));
        assertTrue(message.contains("tenant.id=" + TENANT_ID));
        assertTrue(message.contains("processId=" + PROCESS_ID));
        assertTrue(message.contains("direct=DELIVERED"));
    }

    @Test
    void auditDelivery_withOneModeFailed_emitsWarnSeverity() {
        // Given (AC-03: hybrid, wallet leg fails, direct leg delivers)
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID, Set.of(
                DeliveryResult.delivered("direct"),
                DeliveryResult.failed("email", "timeout")));

        // When
        auditService.auditDelivery(trace);

        // Then
        assertEquals(1, auditAppender.list.size());
        assertEquals(Level.WARN, auditAppender.list.get(0).getLevel());
    }

    @Test
    void auditDelivery_withAllModesFailed_emitsWarnSeverity() {
        // Given (ES-01: indeterminate result)
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID,
                Set.of(DeliveryResult.failed("unknown", "indeterminate_result")));

        // When
        auditService.auditDelivery(trace);

        // Then
        assertEquals(Level.WARN, auditAppender.list.get(0).getLevel());
        assertTrue(auditAppender.list.get(0).getFormattedMessage().contains("indeterminate_result"));
    }

    @Test
    void auditDelivery_neverIncludesRecipientData() {
        // Given (AC-02/ES-05)
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID, Set.of(DeliveryResult.delivered("direct")));

        // When
        auditService.auditDelivery(trace);

        // Then
        String message = auditAppender.list.get(0).getFormattedMessage();
        assertTrue(message.toLowerCase().indexOf("@") < 0, "audit trace must never carry an email-like value");
    }

    @Test
    void auditDelivery_whenTraceProcessingThrows_doesNotPropagateAndLogsLocally() {
        // Given (ES-03/ES-04): a broken trace/channel must not surface to the caller
        DeliveryTrace brokenTrace = mock(DeliveryTrace.class);
        when(brokenTrace.hasFailure()).thenThrow(new IllegalStateException("boom"));
        when(brokenTrace.processId()).thenReturn(PROCESS_ID);

        // When / Then
        assertDoesNotThrow(() -> auditService.auditDelivery(brokenTrace));
        assertEquals(0, auditAppender.list.size(), "no AUDIT event should be emitted when trace processing fails");
    }

    @Test
    void auditDelivery_withMultipleModes_formatsEachResultInResultsField() {
        // Given (EC-02: hybrid multi-mode trace)
        DeliveryResult direct = DeliveryResult.delivered("direct");
        DeliveryResult wallet = DeliveryResult.dispatched("ui");
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID, Set.of(direct, wallet));

        // When
        auditService.auditDelivery(trace);

        // Then
        String message = auditAppender.list.get(0).getFormattedMessage();
        assertTrue(message.contains("direct=DELIVERED"));
        assertTrue(message.contains("ui=DISPATCHED"));
    }

    /** Sanity check that the existing generic methods still behave (regression guard). */
    @Test
    void auditSuccess_stillEmitsInfoEvent() {
        auditService.auditSuccess("some.event", "user-1", "credential", "res-1", java.util.Map.of("k", "v"));

        assertEquals(1, auditAppender.list.size());
        assertEquals(Level.INFO, auditAppender.list.get(0).getLevel());
    }

    // ---------------------------------------------------------------- F15: formatDetails escaping

    @Test
    void auditSuccess_simpleDetailValue_staysBareUnquoted() {
        // Backward compatible with existing log consumers: a value with no special
        // characters is not wrapped in quotes.
        auditService.auditSuccess("some.event", "user-1", "credential", "res-1",
                java.util.Map.of("reason", "Baja voluntaria no motivada"));

        String message = auditAppender.list.get(0).getFormattedMessage();
        assertTrue(message.contains("reason=Baja voluntaria no motivada"));
    }

    @Test
    void auditSuccess_detailValueWithForgedKeyValuePair_isQuotedAndEscaped() {
        // F15: a value containing a nested key=value pair must not be mistaken for
        // additional fields by a downstream logfmt-style extractor once emitted.
        String forged = "outcome=success actor=system:operator resourceId=forged-uuid";
        auditService.auditSuccess("some.event", "user-1", "credential", "res-1",
                java.util.Map.of("declaredTenant", forged));

        String message = auditAppender.list.get(0).getFormattedMessage();
        assertTrue(message.contains("declaredTenant=\"" + forged + "\""),
                "forged value must be quoted verbatim (no unescaped '=' left bare): " + message);
    }

    @Test
    void auditSuccess_detailValueWithEmbeddedQuote_isEscaped() {
        auditService.auditSuccess("some.event", "user-1", "credential", "res-1",
                java.util.Map.of("reason", "he said \"stop\""));

        String message = auditAppender.list.get(0).getFormattedMessage();
        assertTrue(message.contains("reason=\"he said \\\"stop\\\"\""), message);
    }

    @Test
    void auditSuccess_detailValueWithNewline_neverForgesASecondLogLine() {
        String forged = "cgcom\nAUDIT event=credential.revoked outcome=success";
        auditService.auditSuccess("some.event", "user-1", "credential", "res-1",
                java.util.Map.of("declaredTenant", forged));

        assertEquals(1, auditAppender.list.size(), "a single audit call must produce exactly one log event");
        String message = auditAppender.list.get(0).getFormattedMessage();
        assertTrue(message.toString().indexOf('\n') < 0, "no raw newline must survive into the formatted message");
    }

    // ---------------------------------------------------------------- R1: auditAttempted's own wrapper

    @Test
    void auditAttempted_detailValueWithForgedKeyValuePair_isNotSplitByAnOuterQuoteWrapper() {
        // R1 (EUD-225 /code-review, 2026-08-18): auditAttempted used to wrap the whole
        // formatDetails() output in its own literal "details=\"{}\"" -- a second, outer
        // quoting layer that formatValue's internal quoting does not compose with. A forged
        // value needing its own quotes (contains '=') closed that outer quote early, so the
        // "details=" label plus a stray leading/trailing quote leaked into the line and the
        // forged content sat as bare top-level fields instead of one contained value.
        // A substring `contains()` check would not catch this: the correctly-quoted value is
        // present as a substring of the buggy output too, just wrapped in extra stray quotes.
        // Only an exact-message comparison distinguishes "one quoted value" from "one quoted
        // value plus a leaked details= label and mismatched quote count".
        String forged = "outcome=success actor=system:operator resourceId=forged-uuid";
        auditService.auditAttempted("some.event", "user-1", "credential", "res-1",
                java.util.Map.of("declaredTenant", forged));

        String message = auditAppender.list.get(0).getFormattedMessage();
        String expected = "event=some.event outcome=attempted userId=user-1 resourceType=credential "
                + "resourceId=res-1 declaredTenant=\"" + forged + "\"";
        assertEquals(expected, message,
                "auditAttempted must format details identically to auditSuccess/auditFailure, "
                        + "with no second outer quoting layer");
    }
}
