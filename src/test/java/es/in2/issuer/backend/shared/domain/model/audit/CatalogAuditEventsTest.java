package es.in2.issuer.backend.shared.domain.model.audit;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CatalogAuditEventsTest {

    private static final String NONE = CatalogAuditEvents.NO_DECLARED_MODES;

    @Test
    void changes_newConfiguration_isReportedAsEnableWithoutChanges() {
        // Arrange
        Map<String, String> before = Map.of();
        Map<String, String> after = Map.of("learcredential.employee.w3c.4", "email,ui");

        // Act
        List<AuditEntry> entries = CatalogAuditEvents.changes(before, after);

        // Assert
        assertEquals(1, entries.size());
        AuditEntry entry = entries.getFirst();
        assertEquals(AuditEventType.CATALOG_ENTRY_CHANGED, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("Enable", entry.details().get("operation"));
        assertEquals("learcredential.employee.w3c.4", entry.details().get("credential_configuration_id"));
        assertEquals("catalog-entry:learcredential.employee.w3c.4", entry.resource());
        assertFalse(entry.details().containsKey("changes"));
    }

    @Test
    void changes_removedConfiguration_isReportedAsDisable() {
        // Arrange
        Map<String, String> before = Map.of("a", NONE, "b", NONE);
        Map<String, String> after = Map.of("a", NONE);

        // Act
        List<AuditEntry> entries = CatalogAuditEvents.changes(before, after);

        // Assert
        assertEquals(1, entries.size());
        assertEquals("Disable", entries.getFirst().details().get("operation"));
        assertEquals("b", entries.getFirst().details().get("credential_configuration_id"));
    }

    @Test
    void changes_otherDeliveryModes_isReportedAsUpdateWithOldAndNewModes() {
        // Arrange
        Map<String, String> before = Map.of("a", "email");
        Map<String, String> after = Map.of("a", "email,ui");

        // Act
        List<AuditEntry> entries = CatalogAuditEvents.changes(before, after);

        // Assert
        AuditEntry entry = entries.getFirst();
        assertEquals("Update", entry.details().get("operation"));
        assertEquals(Map.of("delivery_modes", Map.of("old", "email", "new", "email,ui")), entry.details().get("changes"));
    }

    @Test
    void changes_modesGoFromDeclaredToInherited_omitTheNewValueInsteadOfInventingOne() {
        // Arrange
        Map<String, String> before = Map.of("a", "email");
        Map<String, String> after = Map.of("a", NONE);

        // Act
        List<AuditEntry> entries = CatalogAuditEvents.changes(before, after);

        // Assert
        assertEquals(Map.of("delivery_modes", Map.of("old", "email")), entries.getFirst().details().get("changes"));
    }

    @Test
    void changes_nothingChanged_reportsNothing() {
        // Arrange
        Map<String, String> same = Map.of("a", "email", "b", NONE);

        // Act
        List<AuditEntry> entries = CatalogAuditEvents.changes(same, same);

        // Assert
        assertTrue(entries.isEmpty());
    }

    @Test
    void changes_severalChanges_areReportedInIdOrderWithTheDisabledLast() {
        // Arrange
        Map<String, String> before = Map.of("old", NONE, "kept", "email");
        Map<String, String> after = Map.of("kept", "ui", "new", NONE);

        // Act
        List<AuditEntry> entries = CatalogAuditEvents.changes(before, after);

        // Assert
        assertEquals(List.of("Update", "Enable", "Disable"),
                entries.stream().map(entry -> (String) entry.details().get("operation")).toList());
    }
}
