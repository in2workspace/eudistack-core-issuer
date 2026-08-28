package es.in2.issuer.backend.issuance.domain.model;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeliveryTraceTest {

    private static final String TENANT_ID = "sandbox";
    private static final String PROCESS_ID = "process-123";

    @Test
    void of_withModeResultAndTenant_buildsTraceWithAllFields() {
        // Given
        Set<DeliveryResult> results = Set.of(DeliveryResult.delivered("direct"));

        // When
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID, results);

        // Then
        assertEquals(TENANT_ID, trace.tenantId());
        assertEquals(PROCESS_ID, trace.processId());
        assertEquals(results, trace.results());
        assertEquals("credential.delivered", DeliveryTrace.EVENT_NAME);
        assertNull(trace.recipientPseudonym());
    }

    @Test
    void of_withBlankTenantId_throwsIllegalArgumentException() {
        Set<DeliveryResult> results = Set.of(DeliveryResult.delivered("direct"));

        assertThrows(IllegalArgumentException.class,
                () -> DeliveryTrace.of(" ", PROCESS_ID, results));
    }

    @Test
    void of_withNullTenantId_throwsIllegalArgumentException() {
        Set<DeliveryResult> results = Set.of(DeliveryResult.delivered("direct"));

        assertThrows(IllegalArgumentException.class,
                () -> DeliveryTrace.of(null, PROCESS_ID, results));
    }

    @Test
    void of_withBlankProcessId_throwsIllegalArgumentException() {
        Set<DeliveryResult> results = Set.of(DeliveryResult.delivered("direct"));

        assertThrows(IllegalArgumentException.class,
                () -> DeliveryTrace.of(TENANT_ID, " ", results));
    }

    @Test
    void of_withEmptyResults_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> DeliveryTrace.of(TENANT_ID, PROCESS_ID, Set.of()));
    }

    @Test
    void of_withNullResults_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> DeliveryTrace.of(TENANT_ID, PROCESS_ID, null));
    }

    @Test
    void results_isDefensivelyCopied_mutatingOriginalSetDoesNotAffectTrace() {
        // Given
        Set<DeliveryResult> mutableResults = new HashSet<>();
        mutableResults.add(DeliveryResult.delivered("direct"));
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID, mutableResults);

        // When
        mutableResults.add(DeliveryResult.dispatched("email"));

        // Then
        assertEquals(1, trace.results().size());
    }

    @Test
    void hasFailure_withAllModesDelivered_returnsFalse() {
        // Given (EC-02: hybrid, both modes succeed)
        Set<DeliveryResult> results = Set.of(
                DeliveryResult.delivered("direct"),
                DeliveryResult.dispatched("email"));
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID, results);

        // Then
        assertFalse(trace.hasFailure());
    }

    @Test
    void hasFailure_withOneModeFailed_returnsTrue() {
        // Given (AC-03: hybrid, wallet leg fails, direct leg delivers)
        Set<DeliveryResult> results = Set.of(
                DeliveryResult.delivered("direct"),
                DeliveryResult.failed("email", "timeout"));
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID, results);

        // Then
        assertTrue(trace.hasFailure());
    }

    @Test
    void hasFailure_withSingleFailedMode_returnsTrue() {
        // Given (ES-01: indeterminate result modeled as a single failed "unknown" mode)
        Set<DeliveryResult> results = Set.of(DeliveryResult.failed("unknown", "indeterminate_result"));
        DeliveryTrace trace = DeliveryTrace.of(TENANT_ID, PROCESS_ID, results);

        // Then
        assertTrue(trace.hasFailure());
    }
}
