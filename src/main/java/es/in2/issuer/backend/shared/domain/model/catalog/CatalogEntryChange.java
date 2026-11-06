package es.in2.issuer.backend.shared.domain.model.catalog;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

/**
 * A committed change to a catalog entry, as the audit trail records it (EUD-266, AC-12): what was done,
 * the entry before it ({@code null} when it was created) and the entry as stored afterwards, with its new
 * version. Both sides show the schema URI the way the API presents it, so a type file that declares none
 * does not make the URI look like it changed.
 */
public record CatalogEntryChange(Operation operation, CatalogEntry before, CatalogEntry after) {

    /** The {@code operation} of the {@code CatalogEntryChanged} audit event (EUD-244), spelled as it documents it. */
    public enum Operation {
        CREATE("Create"),
        UPDATE("Update"),
        ENABLE("Enable"),
        DISABLE("Disable");

        private final String value;

        Operation(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    public CatalogEntryChange {
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(after, "after");
    }

    public static CatalogEntryChange created(CatalogEntry after) {
        return new CatalogEntryChange(Operation.CREATE, null, after);
    }

    public static CatalogEntryChange updated(CatalogEntry before, CatalogEntry after) {
        return new CatalogEntryChange(Operation.UPDATE, before, after);
    }

    /** The operation is the one the entry went through: enabled, disabled, or else updated. */
    public static CatalogEntryChange between(CatalogEntry before, CatalogEntry after) {
        if (before.enabled() == after.enabled()) {
            return new CatalogEntryChange(Operation.UPDATE, before, after);
        }
        return new CatalogEntryChange(after.enabled() ? Operation.ENABLE : Operation.DISABLE, before, after);
    }

    public String credentialConfigurationId() {
        return after.credentialConfigurationId();
    }

    /** {@code true} when no field differs: nothing was changed. */
    public boolean isEmpty() {
        return changes().isEmpty();
    }

    /**
     * The fields that differ, each as {@code [before, after]}, named and shaped as the contract does
     * ({@code delivery_modes}, {@code validity}, {@code subject}, {@code search_identifiers},
     * {@code enabled}, {@code schema_uri}). A created entry has {@code null} before every value.
     */
    public Map<String, List<Object>> changes() {
        Map<String, List<Object>> changes = new LinkedHashMap<>();
        putIfChanged(changes, "schema_uri", CatalogEntry::schemaUri, value -> value);
        putIfChanged(changes, "enabled", CatalogEntry::enabled, value -> value);
        putIfChanged(changes, "delivery_modes", CatalogEntry::deliveryModes, CatalogEntryChange::deliveryModes);
        putIfChanged(changes, "validity", CatalogEntry::validity, CatalogEntryChange::validity);
        putIfChanged(changes, "subject", CatalogEntry::subject, CatalogEntryChange::subject);
        putIfChanged(changes, "search_identifiers", CatalogEntry::searchIdentifiers,
                CatalogEntryChange::searchIdentifiers);
        return changes;
    }

    /**
     * Records the field when its contract-shaped value differs between both sides. A side that has no
     * entry, or no value for the field, is {@code null}.
     */
    private <T> void putIfChanged(Map<String, List<Object>> changes, String field,
                                  Function<CatalogEntry, T> value, Function<T, Object> asContract) {
        putIfDifferent(changes, field, shaped(before, value, asContract), shaped(after, value, asContract));
    }

    private static <T> Object shaped(CatalogEntry entry, Function<CatalogEntry, T> value,
                                     Function<T, Object> asContract) {
        T raw = entry == null ? null : value.apply(entry);
        return raw == null ? null : asContract.apply(raw);
    }

    private static void putIfDifferent(Map<String, List<Object>> changes, String field, Object beforeValue,
                                       Object afterValue) {
        if (!Objects.equals(beforeValue, afterValue)) {
            changes.put(field, Arrays.asList(beforeValue, afterValue));
        }
    }

    private static List<String> deliveryModes(Set<DeliveryMode> deliveryModes) {
        return deliveryModes.stream().map(mode -> mode.value).sorted().toList();
    }

    private static Map<String, Object> validity(CatalogEntry.Validity entryValidity) {
        Map<String, Object> validity = new LinkedHashMap<>();
        validity.put("default_days", entryValidity.defaultDays());
        validity.put("requester_can_set_dates", entryValidity.requesterCanSetDates());
        if (entryValidity.maxDays() != null) {
            validity.put("max_days", entryValidity.maxDays());
        }
        return validity;
    }

    private static Map<String, Object> subject(CatalogEntry.Subject entrySubject) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("fields", entrySubject.fields().stream().map(ClaimPath::segments).toList());
        subject.put("separator", entrySubject.separator());
        return subject;
    }

    private static List<Map<String, Object>> searchIdentifiers(List<CatalogEntry.SearchIdentifier> searchIdentifiers) {
        List<Map<String, Object>> identifiers = new ArrayList<>();
        for (CatalogEntry.SearchIdentifier identifier : searchIdentifiers) {
            Map<String, Object> value = new LinkedHashMap<>();
            value.put("name", identifier.name());
            value.put("field", identifier.field().segments());
            identifiers.add(value);
        }
        return identifiers;
    }
}
