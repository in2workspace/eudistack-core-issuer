package es.in2.issuer.backend.statuslist.application;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Builds the details map for revocation audit events (conv-quality-security-gates.md §10.2).
 * Single point of PII/secret redaction (§10.3) for the attempted/success/failure events emitted
 * by {@link RevocationWorkflow} — never accepts an {@code Issuance} or raw exception, only the
 * primitive identifiers/strings that are safe to log, so email/subject/token can't leak in.
 */
public final class RevocationAuditDetails {

    public static final String REASON_NOT_PROVIDED = "not-provided";
    public static final int MAX_REASON_LENGTH = 280;
    public static final String ACTION_REVOKE = "REVOKE";
    public static final String RESOURCE_TYPE_CREDENTIAL = "Credential";

    /** Default truncation budget for third-party values sanitized only for a log line
     *  or audit detail (not a dedicated field like {@code reason}, which uses its own
     *  {@link #MAX_REASON_LENGTH}). */
    public static final int MAX_LOG_VALUE_LENGTH = 200;

    private static final Pattern CONTROL_CHARS = Pattern.compile("\\p{Cntrl}");

    private RevocationAuditDetails() {
    }

    public static Map<String, Object> toDetailsMap(
            String actor,
            String organizationId,
            String issuanceId,
            String reason,
            String outcome,
            String errorType
    ) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("actor", actor != null ? actor : "unknown");
        details.put("organizationId", organizationId != null ? organizationId : "");
        details.put("resourceType", RESOURCE_TYPE_CREDENTIAL);
        details.put("resourceId", issuanceId);
        details.put("action", ACTION_REVOKE);
        details.put("outcome", outcome);
        details.put("reason", sanitizeReason(reason));
        if (errorType != null && !errorType.isBlank()) {
            details.put("errorType", errorType);
        }
        return Map.copyOf(details);
    }

    static String sanitizeReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return REASON_NOT_PROVIDED;
        }
        return sanitize(reason, MAX_REASON_LENGTH);
    }

    /**
     * Strips control characters (including {@code \n}/{@code \r}) and truncates to
     * {@code maxLength}. Shared by every place third-party message content (a declared
     * tenantId, a messageId, exception text) reaches a log line or an audit detail on the
     * revocation-instruction queue path (F1, EUD-225 {@code /verify}): a raw newline there
     * could forge a second {@code AUDIT} log line that a downstream parser mistakes for a
     * real record. {@code null} is returned as-is — callers decide their own fallback.
     */
    public static String sanitize(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        String normalized = CONTROL_CHARS.matcher(value.trim()).replaceAll("");
        if (normalized.length() <= maxLength) {
            return normalized;
        }
        return normalized.substring(0, maxLength);
    }
}
