package es.in2.issuer.backend.signing.infrastructure.csc.auth;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum CscAuthProvider {

    OAUTH_2("oauth2"),
    VINTEGRIS("vintegris");

    private final String value;

    CscAuthProvider(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static Optional<CscAuthProvider> fromValue(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(valuesAsMap().get(value.toLowerCase()));
    }

    private static Map<String, CscAuthProvider> valuesAsMap() {
        return Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(CscAuthProvider::value, Function.identity()));
    }
}
