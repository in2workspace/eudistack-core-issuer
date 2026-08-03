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
}
