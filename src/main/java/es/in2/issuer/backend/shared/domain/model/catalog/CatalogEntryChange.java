package es.in2.issuer.backend.shared.domain.model.catalog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A committed change to a catalog entry, as the audit trail records it (EUD-266, AC-12): what was done,
 * the entry before it ({@code null} when it was created) and the entry as stored afterwards, with its new
 * version. Both sides show the schema URI the way the API presents it, so a type file that declares none
 * does not make the URI look like it changed.
 */
public record CatalogEntryChange(Action action, CatalogEntry before, CatalogEntry after) {

    public enum Action {
        CREATE("create"),
        REPLACE("replace"),
        ENABLE("enable"),
        DISABLE("disable");

        private final String value;

        Action(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    public CatalogEntryChange {
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(after, "after");
    }

    public static CatalogEntryChange created(CatalogEntry after) {
        return new CatalogEntryChange(Action.CREATE, null, after);
    }

    public static CatalogEntryChange replaced(CatalogEntry before, CatalogEntry after) {
        return new CatalogEntryChange(Action.REPLACE, before, after);
    }

    /** The action is the one the entry went through: enabled, disabled, or else its configuration replaced. */
    public static CatalogEntryChange between(CatalogEntry before, CatalogEntry after) {
        Action action = before.enabled() == after.enabled()
                ? Action.REPLACE
                : after.enabled() ? Action.ENABLE : Action.DISABLE;
        return new CatalogEntryChange(action, before, after);
    }

    public String credentialConfigurationId() {
        return after.credentialConfigurationId();
    }

    /** {@code true} when no field differs: nothing was changed. */
    public boolean isEmpty() {
        return changes().isEmpty();
    }

    /** The version the change left the entry at. */
    public long version() {
        return after.version();
    }

    /**
     * The fields that differ, each as {@code [before, after]}, named and shaped as the contract does
     * ({@code delivery_modes}, {@code validity}, {@code subject}, {@code search_identifiers},
     * {@code enabled}, {@code schema_uri}). A created entry has {@code null} before every value.
     */
    public Map<String, List<Object>> changes() {
        Map<String, List<Object>> changes = new LinkedHashMap<>();
        record(changes, "schema_uri", before == null ? null : before.schemaUri(), after.schemaUri());
        record(changes, "enabled", before == null ? null : before.enabled(), after.enabled());
        record(changes, "delivery_modes", deliveryModes(before), deliveryModes(after));
        record(changes, "validity", validity(before), validity(after));
        record(changes, "subject", subject(before), subject(after));
        record(changes, "search_identifiers", searchIdentifiers(before), searchIdentifiers(after));
        return changes;
    }

    private static void record(Map<String, List<Object>> changes, String field, Object beforeValue, Object afterValue) {
        if (!Objects.equals(beforeValue, afterValue)) {
            changes.put(field, Arrays.asList(beforeValue, afterValue));
        }
    }

    private static List<String> deliveryModes(CatalogEntry entry) {
        if (entry == null || entry.deliveryModes() == null) {
            return null;
        }
        return entry.deliveryModes().stream().map(mode -> mode.value).sorted().toList();
    }

    private static Map<String, Object> validity(CatalogEntry entry) {
        if (entry == null || entry.validity() == null) {
            return null;
        }
        Map<String, Object> validity = new LinkedHashMap<>();
        validity.put("default_days", entry.validity().defaultDays());
        validity.put("requester_can_set_dates", entry.validity().requesterCanSetDates());
        if (entry.validity().maxDays() != null) {
            validity.put("max_days", entry.validity().maxDays());
        }
        return validity;
    }

    private static Map<String, Object> subject(CatalogEntry entry) {
        if (entry == null || entry.subject() == null) {
            return null;
        }
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("fields", entry.subject().fields().stream().map(ClaimPath::segments).toList());
        subject.put("separator", entry.subject().separator());
        return subject;
    }

    private static List<Map<String, Object>> searchIdentifiers(CatalogEntry entry) {
        if (entry == null) {
            return null;
        }
        List<Map<String, Object>> identifiers = new ArrayList<>();
        for (CatalogEntry.SearchIdentifier identifier : entry.searchIdentifiers()) {
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("name", identifier.name());
            value.put("field", identifier.field().segments());
            identifiers.add(value);
        }
        return identifiers;
    }
}
