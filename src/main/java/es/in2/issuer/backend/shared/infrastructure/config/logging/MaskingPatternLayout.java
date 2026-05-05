package es.in2.issuer.backend.shared.infrastructure.config.logging;

import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;

import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class MaskingPatternLayout extends PatternLayout {

    static final String REPLACEMENT = "***";

    private static final List<Map.Entry<Pattern, String>> MASKS = List.of(
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"),
                    REPLACEMENT),
            // Require non-empty segments (+) and allow base64url padding (=)
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile("eyJ[a-zA-Z0-9_\\-=]+\\.[a-zA-Z0-9_\\-=]+\\.[a-zA-Z0-9_\\-=]+"),
                    REPLACEMENT),
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile("(?i)(Bearer\\s+)\\S+"),
                    "$1" + REPLACEMENT),
            // (?<!\\w) prevents matching key names that are substrings of larger words (e.g. notsecret=).
            // client_secret is listed before secret to avoid premature alternation short-circuit.
            new AbstractMap.SimpleImmutableEntry<>(
                    Pattern.compile(
                            "(?i)(?<!\\w)(\"?(?:tx_code|access_token|refresh_token|password"
                                    + "|client_secret|secret)\"?\\s*[:=]\\s*\"?)([^\"&\\s,}]+)"),
                    "$1" + REPLACEMENT)
    );

    // PatternLayout override
    @Override
    public String doLayout(ILoggingEvent event) {
        return mask(super.doLayout(event));
    }

    // Shared masking logic
    static String mask(final String input) {
        if (input == null || input.isBlank()) {
            return input;
        }
        String result = input;
        for (Map.Entry<Pattern, String> entry : MASKS) {
            result = entry.getKey().matcher(result).replaceAll(entry.getValue());
        }
        return result;
    }
}

