package es.in2.issuer.backend.statuslist.domain.util;

import java.util.regex.Pattern;

/**
 * Makes a value that comes from outside safe for a log line written as {@code key=value} pairs.
 * Neutral on purpose: an adapter and an application service use it alike without one depending
 * on the other.
 */
public final class LogSanitizer {

    /** Default truncation budget for a value sanitized for a log line or an audit detail. */
    public static final int MAX_VALUE_LENGTH = 200;

    /**
     * {@code \p{Cntrl}} is ASCII-only in Java (\x00-\x1F, \x7F) and misses the Unicode line and
     * paragraph separators that some log viewers still treat as line breaks (NEL U+0085, LS U+2028,
     * PS U+2029), the exact characters this sanitizer exists to strip.
     */
    public static final Pattern FORBIDDEN_LOG_CHARS = Pattern.compile("[\\p{Cntrl}\\u0085\\u2028\\u2029]");

    // Same trigger set as AuditServiceImpl's formatValue: a value with none of these stays bare.
    private static final Pattern NEEDS_QUOTING = Pattern.compile("[\"=\\p{Cntrl}\\u0085\\u2028\\u2029]");

    private LogSanitizer() {
    }

    /**
     * Strips control characters (including {@code \n} and {@code \r}) and truncates to
     * {@code maxLength} code points. A raw newline could forge a second log line that a parser
     * mistakes for a real record. {@code null} is returned as-is: callers decide their fallback.
     */
    public static String sanitize(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        // FORBIDDEN_LOG_CHARS already covers \n and \r. The literal replacements are there because CodeQL
        // java/log-injection only recognizes those as removing line breaks, not a compiled Pattern.
        String withoutLineBreaks = value.trim().replace("\n", "").replace("\r", "");
        String normalized = FORBIDDEN_LOG_CHARS.matcher(withoutLineBreaks).replaceAll("");
        // Counted in code points: a UTF-16 cut could split a surrogate pair.
        if (normalized.codePointCount(0, normalized.length()) <= maxLength) {
            return normalized;
        }
        return normalized.substring(0, normalized.offsetByCodePoints(0, maxLength));
    }

    /**
     * {@link #sanitize} and, when the value has a {@code "} or an {@code =}, quotes and escapes it the
     * way the AUDIT sink does, so it cannot forge extra {@code key=value} fields (CodeQL
     * java/log-injection). Well-formed UUIDs and identifiers stay bare.
     */
    public static String quoteIfNeeded(String value, int maxLength) {
        String truncated = sanitize(value, maxLength);
        if (truncated == null || !NEEDS_QUOTING.matcher(truncated).find()) {
            return truncated;
        }
        String escaped = truncated.replace("\\", "\\\\").replace("\"", "\\\"");
        return "\"" + escaped + "\"";
    }
}
