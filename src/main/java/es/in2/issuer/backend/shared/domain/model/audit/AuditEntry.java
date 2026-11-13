package es.in2.issuer.backend.shared.domain.model.audit;

import es.in2.issuer.backend.shared.domain.exception.InvalidAuditEntryException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * What a use case knows about an auditable fact: the event type, the object it is about, the outcome
 * and the type's {@code details}. The tenant, actor, organization and correlation id are not part of
 * it: they come from the audit context of the operation.
 *
 * <p>The catalogue rules are enforced on construction: a non-success entry needs a reason from the
 * type's vocabulary, and that reason fixes the result. A detail left {@code null} is omitted, because a
 * field the step did not get to know is never sent.
 *
 * @param source the producing system; defaults to the one the event type belongs to
 */
public record AuditEntry(
        AuditEventType type,
        String source,
        String resource,
        AuditResult result,
        String reason,
        Map<String, Object> details
) {

    public AuditEntry {
        Objects.requireNonNull(type, "type is required");
        Objects.requireNonNull(result, "result is required");
        if (resource == null || resource.isBlank()) {
            throw new InvalidAuditEntryException("An audit entry needs the resource it is about");
        }
        source = source == null || source.isBlank() ? type.defaultSource() : source;
        requireConsistentReason(type, result, reason);
        details = withoutNullValues(details);
    }

    public static AuditEntry success(AuditEventType type, String resource, Map<String, Object> details) {
        return new AuditEntry(type, null, resource, AuditResult.SUCCESS, null, details);
    }

    public static AuditEntry denied(AuditEventType type, String resource, String reason,
                                    Map<String, Object> details) {
        return new AuditEntry(type, null, resource, AuditResult.DENIED, reason, details);
    }

    public static AuditEntry failure(AuditEventType type, String resource, String reason,
                                     Map<String, Object> details) {
        return new AuditEntry(type, null, resource, AuditResult.FAILURE, reason, details);
    }

    /** A non-success entry whose result is the one the catalogue fixes for {@code reason} in this type. */
    public static AuditEntry forReason(AuditEventType type, String resource, String reason,
                                       Map<String, Object> details) {
        AuditResult result = type.resultFor(reason).orElseThrow(() -> new InvalidAuditEntryException(
                reason + " is not a reason of " + type.catalogName()));
        return new AuditEntry(type, null, resource, result, reason, details);
    }

    public AuditEntry withSource(String newSource) {
        return new AuditEntry(type, newSource, resource, result, reason, details);
    }

    private static void requireConsistentReason(AuditEventType type, AuditResult result, String reason) {
        if (result == AuditResult.SUCCESS) {
            if (reason != null) {
                throw new InvalidAuditEntryException(type.catalogName() + ": a successful entry carries no reason");
            }
            return;
        }
        if (reason == null || reason.isBlank()) {
            throw new InvalidAuditEntryException(type.catalogName() + ": a " + result + " entry needs a reason");
        }
        AuditResult determined = type.resultFor(reason).orElseThrow(() -> new InvalidAuditEntryException(
                reason + " is not a reason of " + type.catalogName()));
        if (determined != result) {
            throw new InvalidAuditEntryException(
                    reason + " determines the result " + determined + " for " + type.catalogName() + ", not " + result);
        }
    }

    private static Map<String, Object> withoutNullValues(Map<String, Object> source) {
        Map<String, Object> copy = new LinkedHashMap<>();
        if (source == null) {
            return Collections.emptyMap();
        }
        source.forEach((key, value) -> {
            Object cleaned = cleaned(value);
            if (cleaned != null) {
                copy.put(key, cleaned);
            }
        });
        return Collections.unmodifiableMap(copy);
    }

    @SuppressWarnings("unchecked")
    private static Object cleaned(Object value) {
        if (value instanceof Map<?, ?> nested) {
            return withoutNullValues((Map<String, Object>) nested);
        }
        if (value instanceof List<?> list) {
            List<Object> cleanedList = new ArrayList<>();
            list.forEach(element -> {
                Object cleanedElement = cleaned(element);
                if (cleanedElement != null) {
                    cleanedList.add(cleanedElement);
                }
            });
            return Collections.unmodifiableList(cleanedList);
        }
        return value;
    }
}
