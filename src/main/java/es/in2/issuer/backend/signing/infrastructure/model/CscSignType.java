package es.in2.issuer.backend.signing.infrastructure.model;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum CscSignType {

    CSC_SIGN_HASH("sign-hash"),
    CSC_SIGN_DOC("sign-doc");

    private final String value;

    CscSignType(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static CscSignType fromValue(String value) {

        CscSignType provider = valuesAsMap().get(value);

        if (provider == null) {
            throw new IllegalArgumentException(
                    "Unsupported CSC signing type: " + value
            );
        }

        return provider;
    }

    private static Map<String, CscSignType> valuesAsMap() {

        return Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(
                        CscSignType::value,
                        Function.identity()
                ));
    }
}