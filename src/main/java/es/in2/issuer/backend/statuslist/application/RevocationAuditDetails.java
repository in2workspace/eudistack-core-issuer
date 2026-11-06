package es.in2.issuer.backend.statuslist.application;

import es.in2.issuer.backend.statuslist.domain.util.LogSanitizer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Builds the details map for revocation audit events (conv-quality-security-gates.md §10.2).
 * Single point of PII/secret redaction (§10.3) for the attempted/success/failure events emitted
 * by {@link RevocationWorkflow} — never accepts an {@code Issuance} or raw exception, only the
 * primitive identifiers/strings that are safe to log, so a token or the attestation can't leak in.
 * The holder is not traced here: their name, email and document reach the encrypted audit store
 * through the audit events of EUD-244, not these log events (EUD-247 AC-13).
 */
public final class RevocationAuditDetails {

    public static final String REASON_NOT_PROVIDED = "not-provided";
    public static final int MAX_REASON_LENGTH = 280;
    public static final String ACTION_REVOKE = "REVOKE";
    public static final String RESOURCE_TYPE_CREDENTIAL = "Credential";

    /** Default truncation budget for third-party values sanitized only for a log line
     *  or audit detail (not a dedicated field like {@code reason}, which uses its own
     *  {@link #MAX_REASON_LENGTH}). */
    public static final int MAX_LOG_VALUE_LENGTH = LogSanitizer.MAX_VALUE_LENGTH;

    /** Marker substituted for {@code declaredTenant} when it fails {@link #TENANT_NAME_PATTERN}
     *  (F15, EUD-225 {@code /verify}) — the raw value never reaches the audit detail map;
     *  {@code declaredTenantSha256} preserves forensic correlation instead. */
    public static final String DECLARED_TENANT_NON_CONFORMING_MARKER = "non-conforming";

    /** Kept for the callers of the revocation-instruction queue: the definition lives in {@link LogSanitizer}. */
    public static final Pattern FORBIDDEN_LOG_CHARS = LogSanitizer.FORBIDDEN_LOG_CHARS;

    // Same criterion as TenantDomainWebFilter's tenant name pattern, bounded to a
    // reasonable length -- a legitimate tenant identifier already has to satisfy this, so
    // a non-conforming declaredTenant is itself evidence of a forged/malformed value (F15).
    private static final Pattern TENANT_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

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

    /** See {@link LogSanitizer#sanitize}. */
    public static String sanitize(String value, int maxLength) {
        return LogSanitizer.sanitize(value, maxLength);
    }

    /** See {@link LogSanitizer#quoteIfNeeded}: for the plain log lines of {@link RevocationWorkflow}. */
    public static String quoteIfNeeded(String value, int maxLength) {
        return LogSanitizer.quoteIfNeeded(value, maxLength);
    }

    /**
     * F15 (EUD-225 {@code /verify}): {@link #sanitize(String, int)} alone (control-char
     * stripping) does not stop a {@code declaredTenant} containing spaces/{@code =} from
     * forging extra {@code key=value} fields inside a real audit line once it reaches
     * {@code AuditServiceImpl.formatDetails} — that sink now also quotes/escapes, but
     * {@code declaredTenant} specifically gets a stricter treatment here: a legitimate
     * tenant identifier already has to satisfy {@link #TENANT_NAME_PATTERN} (same
     * criterion as {@code TenantDomainWebFilter}), so a value that doesn't is itself
     * evidence of tampering and is never placed in the audit detail map verbatim — a
     * fixed marker plus a SHA-256 digest of the original value preserve forensic
     * correlation (the same forged input always hashes the same way) without the audit
     * detail ever acquiring field syntax.
     */
    public static Map<String, Object> declaredTenantAuditFields(String declaredTenant) {
        if (declaredTenant != null && TENANT_NAME_PATTERN.matcher(declaredTenant).matches()) {
            return Map.of("declaredTenant", declaredTenant);
        }
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("declaredTenant", DECLARED_TENANT_NON_CONFORMING_MARKER);
        fields.put("declaredTenantSha256", sha256Hex(declaredTenant));
        return fields;
    }

    private static String sha256Hex(String value) {
        if (value == null) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is a mandatory JCE algorithm on every JDK distribution the platform
            // targets -- this is not a real runtime path, only a compiler-required catch.
            throw new IllegalStateException("SHA-256 MessageDigest unavailable", e);
        }
    }
}
