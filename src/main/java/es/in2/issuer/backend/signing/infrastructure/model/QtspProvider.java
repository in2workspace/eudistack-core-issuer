package es.in2.issuer.backend.signing.infrastructure.model;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum QtspProvider {

    OAUTH_2("oauth2"),
    VINTEGRIS("vintegris");

    private final String value;

    QtspProvider(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static Optional<QtspProvider> fromValue(String value) {

        if (value == null || value.isBlank()) {
            return Optional.empty();
        }

        return Optional.ofNullable(
                valuesAsMap().get(value.toLowerCase())
        );
    }

    private static Map<String, QtspProvider> valuesAsMap() {

        return java.util.Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(
                        QtspProvider::value,
                        Function.identity()
                ));
    }
}