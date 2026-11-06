package es.in2.issuer.backend.shared.domain.model.audit;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;

/**
 * Builds the {@code CatalogEntryChanged} entries of a replacement of the tenant catalogue. The catalogue is
 * replaced as a whole, but the audit trail reports one entry per credential configuration that changed:
 * enabled, disabled, or kept with other delivery modes. An entry that stays as it was is not reported.
 *
 * <p>Only enabled configurations are stored (the others are deleted), so a configuration is never told
 * apart as created; it is {@code Enable}.
 */
public final class CatalogAuditEvents {

    /** The stored delivery modes of a configuration that declares none, which inherit the schema default. */
    public static final String NO_DECLARED_MODES = "";

    private CatalogAuditEvents() {
    }

    /**
     * @param before enabled configuration id to its stored delivery modes, {@link #NO_DECLARED_MODES} if none
     * @param after  the same, as the replacement leaves it
     */
    public static List<AuditEntry> changes(Map<String, String> before, Map<String, String> after) {
        List<AuditEntry> entries = new ArrayList<>();
        new TreeSet<>(after.keySet()).forEach(id -> {
            if (!before.containsKey(id)) {
                entries.add(entry(id, "Enable", null));
            } else if (!Objects.equals(before.get(id), after.get(id))) {
                entries.add(entry(id, "Update", modesChange(before.get(id), after.get(id))));
            }
        });
        new TreeSet<>(before.keySet()).stream()
                .filter(id -> !after.containsKey(id))
                .forEach(id -> entries.add(entry(id, "Disable", null)));
        return entries;
    }

    private static Map<String, Object> modesChange(String oldModes, String newModes) {
        Map<String, Object> modes = new LinkedHashMap<>();
        modes.put("old", NO_DECLARED_MODES.equals(oldModes) ? null : oldModes);
        modes.put("new", NO_DECLARED_MODES.equals(newModes) ? null : newModes);
        return Map.of("delivery_modes", modes);
    }

    private static AuditEntry entry(String credentialConfigurationId, String operation, Map<String, Object> changes) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("operation", operation);
        details.put("credential_configuration_id", credentialConfigurationId);
        details.put("changes", changes);
        return AuditEntry.success(AuditEventType.CATALOG_ENTRY_CHANGED,
                "catalog-entry:" + credentialConfigurationId, details);
    }
}
