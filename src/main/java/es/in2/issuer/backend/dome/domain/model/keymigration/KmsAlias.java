package es.in2.issuer.backend.dome.domain.model.keymigration;

import java.util.regex.Pattern;

public record KmsAlias(String value) {

    private static final Pattern ALIAS_PATTERN = Pattern.compile("alias/[a-zA-Z0-9/_-]+");

    public KmsAlias {
        if (value == null || !ALIAS_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    "KmsAlias must match pattern 'alias/[a-zA-Z0-9/_-]+', got: " + value);
        }
    }
}

