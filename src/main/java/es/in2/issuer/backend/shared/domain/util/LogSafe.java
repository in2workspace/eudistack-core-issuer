package es.in2.issuer.backend.shared.domain.util;

import java.util.regex.Pattern;

/**
 * A value taken from a request (a token claim, a header) made safe to write in a log line: control
 * characters, line breaks among them, are replaced so the value cannot forge another log line.
 */
public final class LogSafe {

    private static final Pattern CONTROL = Pattern.compile("\\p{Cntrl}");

    private LogSafe() {
    }

    public static String of(String value) {
        return value == null ? null : CONTROL.matcher(value).replaceAll("_");
    }
}
